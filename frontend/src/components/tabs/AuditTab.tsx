'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';
import { Search, Filter, ChevronLeft, ChevronRight, Clock, User, Activity, FileText } from 'lucide-react';
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

    const { data, isLoading, error } = useSWR<AuditResponse>(buildKey(), {
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
                    const data = await res.json();
                    setSelectedAction(data);
                } else {
                    addToast('Failed to load action details', 'error');
                }
            } catch (err) {
                addToast('Network error loading action', 'error');
            } finally {
                setIsFetchingDetail(false);
            }
        } else if (entry.target_type === 'service') {
            setSelectedService(entry.target_id);
        }
    };

    const availableActions = Object.keys(ACTION_BADGE_MAP);

    // Loading state
    if (isLoading && !data) {
        return (
            <div className="space-y-4">
                <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Audit Trail</h2>
                <div className="glass-card p-8 rounded-2xl border border-white/[0.08]">
                    <div className="flex items-center justify-center gap-3 text-slate-400">
                        <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                        <span>Loading audit entries...</span>
                    </div>
                </div>
            </div>
        );
    }

    // Error state
    if (error) {
        return (
            <div className="space-y-4">
                <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Audit Trail</h2>
                <div className="glass-card p-8 rounded-2xl border border-red-500/20 bg-red-500/5">
                    <div className="text-center">
                        <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-red-500/10 flex items-center justify-center">
                            <Activity className="w-6 h-6 text-red-400" />
                        </div>
                        <p className="text-red-400 font-medium">Failed to load audit log</p>
                        <p className="text-sm text-slate-500 mt-1">Check admin access and backend connectivity.</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Audit Trail</h2>
                    <p className="text-sm text-slate-400 mt-1">
                        {total} total events recorded
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="glass-card rounded-2xl border border-white/[0.08] p-4">
                <div className="flex flex-col sm:flex-row gap-3">
                    {/* Username search */}
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                            type="text"
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                            placeholder="Filter by actor..."
                            className="w-full pl-10 pr-4 py-2.5 bg-white/[0.03] border border-white/[0.08] rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all"
                        />
                    </div>

                    {/* Action filter */}
                    <div className="relative">
                        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <select
                            value={actionFilter}
                            onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}
                            className="pl-10 pr-8 py-2.5 bg-white/[0.03] border border-white/[0.08] rounded-xl text-sm text-slate-200 focus:outline-none focus:border-indigo-500/50 appearance-none cursor-pointer min-w-[180px]"
                        >
                            <option value="">All Actions</option>
                            {availableActions.map(a => (
                                <option key={a} value={a}>{ACTION_BADGE_MAP[a].label}</option>
                            ))}
                        </select>
                    </div>

                    {/* Search button */}
                    <button
                        onClick={handleSearch}
                        className="px-4 py-2.5 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 rounded-xl text-sm font-medium border border-indigo-500/20 transition-all"
                    >
                        Search
                    </button>
                </div>
            </div>

            {/* Table */}
            <div className="glass-card rounded-2xl border border-white/[0.08] overflow-hidden">
                {entries.length === 0 ? (
                    <div className="p-12 text-center">
                        <FileText className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                        <p className="text-sm text-slate-400">No audit entries found.</p>
                        <p className="text-xs text-slate-500 mt-1">Try adjusting your filters.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-white/[0.06]">
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                                        <div className="flex items-center gap-1.5"><Clock size={12} /> Time</div>
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                                        <div className="flex items-center gap-1.5"><User size={12} /> Actor</div>
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Action</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Target</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Detail</th>
                                    <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">IP</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04]">
                                {entries.map((entry) => (
                                    <tr 
                                        key={entry.id} 
                                        className={`transition-colors ${entry.target_type === 'pending_action' || entry.target_type === 'service' ? 'hover:bg-white/[0.06] cursor-pointer' : 'hover:bg-white/[0.02]'}`}
                                        onClick={() => handleRowClick(entry)}
                                    >
                                        <td className="px-4 py-3 text-slate-400 whitespace-nowrap font-mono text-xs">
                                            {formatTimestamp(entry.created_at)}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-slate-200 font-medium">{entry.username}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <ActionBadge action={entry.action} />
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-slate-300 text-xs font-mono">
                                                {entry.target_type}/{entry.target_id}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-slate-400 text-xs max-w-[200px] truncate block" title={entry.detail}>
                                                {entry.detail || '—'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-slate-500 text-xs font-mono">{entry.ip_address}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.06]">
                        <span className="text-xs text-slate-500">
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
                            <span className="text-xs text-slate-400 font-medium px-2">
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
                            } catch (e) {}
                        }
                    }
                    apiFetch(`/api/v1/admin/actions/${id}/approve`, { method: 'POST' }).then(() => {
                        addToast('Action authorized', 'success');
                        setSelectedAction(null);
                    }).catch(() => addToast('Failed to authorize action', 'error'));
                }}
                onReject={(id) => {
                    apiFetch(`/api/v1/admin/actions/${id}/reject`, { method: 'POST' }).then(() => {
                        addToast('Action rejected', 'success');
                        setSelectedAction(null);
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
