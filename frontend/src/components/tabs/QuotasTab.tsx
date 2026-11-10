'use client';

import React, { useRef, useState } from 'react';
import useSWR from 'swr';
import {
    HardDrive,
    RefreshCw,
    Edit3,
    Search,
    Database,
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';
import { Modal } from '@/components/ui/Modal';
import ResponsiveSummary from '@/components/ui/ResponsiveSummary';

export interface UserQuotaRecord {
    user_id: number;
    username: string;
    quota_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_pct: number;
    configured: boolean;
    status: string;
    source: string;
    updated_at?: string;
    usedGB?: number;
    totalGB?: number;
    percentage?: number;
}

const fetcher = (url: string) => apiFetch(url).then(res => res.json());

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export default function QuotasTab() {
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');

    // SWR Data Fetching
    const {
        data: quotasData,
        isLoading: quotasLoading,
        mutate: mutateQuotas
    } = useSWR<{ quotas: UserQuotaRecord[] }>('/api/v1/admin/quotas', fetcher, {
        refreshInterval: 15000,
    });

    const quotas = quotasData?.quotas || [];

    // Edit Quota Modal State
    const [selectedQuota, setSelectedQuota] = useState<UserQuotaRecord | null>(null);
    const [quotaInput, setQuotaInput] = useState('');
    const quotaDraftRevision = useRef(0);
    const quotaInputRef = useRef<HTMLInputElement>(null);
    const [isSavingQuota, setIsSavingQuota] = useState(false);

    // Refreshing state tracking per user
    const [refreshingUserId, setRefreshingUserId] = useState<number | null>(null);

    const handleRefreshQuota = async (userId: number, username: string) => {
        setRefreshingUserId(userId);
        try {
            const res = await apiFetch(`/api/v1/admin/quotas/${userId}/refresh`, { method: 'POST' });
            if (!res.ok) throw new Error('Refresh failed');
            addToast(`Storage scan completed for ${username}.`, 'success');
            mutateQuotas();
        } catch {
            addToast(`Failed to scan disk quota for ${username}.`, 'error');
        } finally {
            setRefreshingUserId(null);
        }
    };

    const handleOpenEditModal = (quota: UserQuotaRecord) => {
        quotaDraftRevision.current += 1;
        setSelectedQuota(quota);
        const exactUnits = [
            { unit: 'TB', divisor: 1024 ** 4 },
            { unit: 'GB', divisor: 1024 ** 3 },
            { unit: 'MB', divisor: 1024 ** 2 },
            { unit: 'KB', divisor: 1024 },
        ];
        const exactUnit = exactUnits.find(({ divisor }) => quota.quota_bytes > 0 && quota.quota_bytes % divisor === 0);
        setQuotaInput(exactUnit ? `${quota.quota_bytes / exactUnit.divisor}${exactUnit.unit}` : `${quota.quota_bytes}B`);
    };

    const handleSaveQuota = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedQuota || isSavingQuota) return;
        const submittedRevision = quotaDraftRevision.current;

        setIsSavingQuota(true);
        try {
            const res = await apiFetch(`/api/v1/admin/quotas/${selectedQuota.user_id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    quota: quotaInput.trim(),
                    source: 'manual',
                }),
            });
            if (!res.ok) throw new Error('Update failed');
            addToast(`Storage quota for ${selectedQuota.username} updated to ${quotaInput}.`, 'success');
            if (quotaDraftRevision.current === submittedRevision) setSelectedQuota(null);
            mutateQuotas();
        } catch {
            addToast('Failed to update disk quota.', 'error');
        } finally {
            setIsSavingQuota(false);
        }
    };

    const filteredQuotas = quotas.filter(q =>
        q.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        String(q.user_id).includes(searchQuery)
    );

    // Summary calculations
    const totalAllocatedBytes = quotas.reduce((acc, q) => acc + (q.quota_bytes || 0), 0);
    const totalUsedBytes = quotas.reduce((acc, q) => acc + (q.used_bytes || 0), 0);
    const configuredUsersCount = quotas.filter(q => q.configured || q.quota_bytes > 0).length;

    return (
        <div className="animate-fade-in relative z-10 w-full min-w-0 pb-10 text-slate-100">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/[0.07] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="w-10 h-10 rounded-xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shrink-0">
                        <HardDrive size={20} />
                    </div>
                    <div>
                        <h2 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                            Storage Quotas
                        </h2>
                        <p className="text-xs text-slate-400 mt-0.5">
                            User disk allocation, capacity thresholds, and automated space recalculations.
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <span className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 flex items-center gap-2">
                        <Database size={13} className="text-indigo-400" />
                        <span>Disk Quotas ({quotas.length})</span>
                    </span>
                    <button
                        type="button"
                        onClick={() => mutateQuotas()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all min-h-[36px]"
                        title="Refresh Quotas"
                    >
                        <RefreshCw size={13} className={quotasLoading ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            <ResponsiveSummary label={`Storage summary · ${formatBytes(totalUsedBytes)} used`}>
                <div className="min-w-0 rounded-none shadow-none bg-transparent border-b border-white/[0.07] grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.07]">
                    <div className="p-4 sm:p-5 flex flex-col justify-center min-w-0">
                        <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block">Total Allocated Storage</span>
                        <span className="text-xl font-mono font-bold text-white mt-1 block">
                            {formatBytes(totalAllocatedBytes)}
                        </span>
                        <span className="text-xs text-slate-500 mt-0.5">Aggregate user quota ceilings</span>
                    </div>
                    <div className="p-4 sm:p-5 flex flex-col justify-center min-w-0">
                        <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block">Current Storage Consumption</span>
                        <span className="text-xl font-mono font-bold text-cyan-300 mt-1 block">
                            {formatBytes(totalUsedBytes)}
                        </span>
                        <span className="text-xs text-slate-500 mt-0.5">Scanned filesystem footprints</span>
                    </div>
                    <div className="p-4 sm:p-5 flex flex-col justify-center min-w-0">
                        <span className="text-xs text-slate-400 font-medium uppercase tracking-wider block">Quota Enforcement Status</span>
                        <div className="flex items-center gap-2 mt-1">
                            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                            <span className="text-base font-semibold text-emerald-300">
                                {configuredUsersCount} Configured / Active
                            </span>
                        </div>
                        <span className="text-xs text-slate-500 mt-0.5">Active POSIX / system limit boundaries</span>
                    </div>
                </div>
            </ResponsiveSummary>

            {/* Filter Search Bar */}
            <div className="py-3.5 border-b border-white/[0.07] relative">
                <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                <input
                    type="text"
                    placeholder="Search users or IDs..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-white/[0.03] border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 transition-colors min-h-[44px]"
                />
            </div>

            <div className="min-w-0 rounded-none shadow-none bg-transparent border-b border-white/[0.07] divide-y divide-white/[0.07]">
                {quotasLoading && quotas.length === 0 ? (
                    <div className="p-12 text-center text-slate-400 text-xs flex items-center justify-center gap-3">
                        <RefreshCw size={16} className="animate-spin text-indigo-400" />
                        <span>Loading storage quota records...</span>
                    </div>
                ) : filteredQuotas.length === 0 ? (
                    <div className="p-16 text-center space-y-2">
                        <Database size={32} className="mx-auto text-slate-600" />
                        <h4 className="text-sm font-semibold text-slate-300">No Quota Records Found</h4>
                        <p className="text-xs text-slate-500 max-w-sm mx-auto">
                            {searchQuery ? `No user matches query "${searchQuery}".` : 'No storage quotas have been registered yet.'}
                        </p>
                    </div>
                ) : (
                    filteredQuotas.map((quota) => {
                        const rawUsagePct = quota.usage_pct ?? quota.percentage ?? (quota.quota_bytes > 0 ? (quota.used_bytes / quota.quota_bytes) * 100 : 0);
                        const usagePct = Number.isFinite(rawUsagePct) ? Math.max(0, rawUsagePct) : 0;
                        const isWarning = usagePct >= 80 && usagePct < 95;
                        const isDanger = usagePct >= 95;

                        return (
                            <div
                                key={quota.user_id}
                                data-quota-row="true"
                                className="p-4 sm:p-5 hover:bg-white/[0.02] grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)_auto] md:items-center gap-4 transition-colors min-w-0"
                            >
                                <div className="flex items-center gap-3.5 min-w-0 max-w-full">
                                    <div className="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center font-bold text-slate-200 shrink-0">
                                        {quota.username.substring(0, 2).toUpperCase()}
                                    </div>
                                    <div className="min-w-0">
                                        <div className="flex items-center gap-2 min-w-0">
                                            <span className="min-w-0 font-semibold text-sm text-white break-words [overflow-wrap:anywhere]">{quota.username}</span>
                                            <span className="text-xs font-mono text-slate-500 shrink-0">#{quota.user_id}</span>
                                        </div>
                                        <div className="flex items-center gap-2 mt-0.5">
                                            <span className="text-xs text-slate-400">
                                                {quota.quota_bytes > 0 ? (
                                                    <span className="font-mono">{formatBytes(quota.used_bytes)} / {formatBytes(quota.quota_bytes)}</span>
                                                ) : (
                                                    <span className="text-slate-500 italic">No quota bound</span>
                                                )}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                <div className="w-full space-y-1.5 min-w-0">
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="text-slate-400">Utilization</span>
                                        <span className={`font-bold ${isDanger ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-cyan-400'}`}>
                                            {usagePct.toFixed(1)}%
                                        </span>
                                    </div>
                                    <div role="progressbar" aria-label={`${quota.username} storage utilization`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, Math.max(0, usagePct))} aria-valuetext={`${usagePct.toFixed(1)}%`} className="w-full h-2 rounded-full bg-white/5 overflow-hidden border border-white/5">
                                        <div
                                            className={`h-full rounded-full transition-all duration-500 ${
                                                isDanger
                                                    ? 'bg-gradient-to-r from-rose-500 to-rose-400 shadow-[0_0_8px_#f43f5e]'
                                                    : isWarning
                                                    ? 'bg-gradient-to-r from-amber-500 to-amber-400 shadow-[0_0_8px_#fbbf24]'
                                                    : 'bg-gradient-to-r from-indigo-500 to-cyan-400 shadow-[0_0_8px_#6366f1]'
                                            }`}
                                            style={{ width: `${Math.min(100, Math.max(0, usagePct))}%` }}
                                        />
                                    </div>
                                </div>

                                {/* Actions */}
                                <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                                    <button
                                        type="button"
                                        disabled={refreshingUserId === quota.user_id}
                                        onClick={() => handleRefreshQuota(quota.user_id, quota.username)}
                                        className="obs-touch-target-standard px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] text-slate-200 hover:text-white border border-white/10 flex items-center gap-1.5 transition-all min-h-[40px]"
                                        title="Scan disk to recalculate used space"
                                    >
                                        <RefreshCw
                                            size={13}
                                            className={refreshingUserId === quota.user_id ? 'animate-spin text-indigo-400' : 'text-slate-400'}
                                        />
                                        <span>Scan Disk</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => handleOpenEditModal(quota)}
                                        className="obs-touch-target-standard px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 hover:text-indigo-200 border border-indigo-500/30 flex items-center gap-1.5 transition-all min-h-[40px]"
                                    >
                                        <Edit3 size={13} />
                                        <span>Edit Quota</span>
                                    </button>
                                </div>
                            </div>
                        );
                    })
                )}
            </div>

            {/* MODAL: EDIT DISK QUOTA */}
            {selectedQuota && (
                <Modal
                    isOpen
                    onClose={() => { quotaDraftRevision.current += 1; setSelectedQuota(null); }}
                    title="Update Disk Quota"
                    initialFocusRef={quotaInputRef}
                    className="max-w-md"
                >
                        <form onSubmit={handleSaveQuota} className="space-y-4">
                            <div>
                                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-1">
                                    Target User
                                </label>
                                <div className="p-3 bg-white/[0.03] border border-white/10 rounded-xl text-sm font-semibold text-white flex items-center justify-between">
                                    <span className="min-w-0 break-words [overflow-wrap:anywhere]">{selectedQuota.username}</span>
                                    <span className="shrink-0 text-xs font-mono text-slate-400">ID: #{selectedQuota.user_id}</span>
                                </div>
                            </div>

                            <div>
                                <label htmlFor="quota-allocation" className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Allocated Disk Space
                                </label>
                                <input
                                    id="quota-allocation"
                                    ref={quotaInputRef}
                                    type="text"
                                    required
                                    placeholder="e.g. 50GB, 250GB, 1TB"
                                    value={quotaInput}
                                    onChange={(e) => { quotaDraftRevision.current += 1; setQuotaInput(e.target.value); }}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 font-mono min-h-[44px]"
                                />
                                <p className="text-sm text-slate-300 mt-2">
                                    Current allocation: {formatBytes(selectedQuota.quota_bytes)}
                                    <span className="block text-xs text-slate-400 font-mono mt-1">{selectedQuota.quota_bytes.toLocaleString()} bytes exactly</span>
                                </p>
                                <span className="text-xs text-slate-400 mt-2 block">
                                    Accepts sizes like 100GB, 500GB, 2TB or exact bytes. Filesystem limits round up to the nearest 1 KiB.
                                </span>
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={() => { quotaDraftRevision.current += 1; setSelectedQuota(null); }}
                                    className="obs-touch-target-standard px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-white/5 transition-colors min-h-[44px]"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSavingQuota}
                                    data-tone="primary"
                                    className="glass-button obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2 text-xs font-bold disabled:opacity-50 min-h-[44px]"
                                >
                                    {isSavingQuota ? 'Saving...' : 'Apply Quota'}
                                </button>
                            </div>
                        </form>
                </Modal>
            )}
        </div>
    );
}
