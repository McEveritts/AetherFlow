'use client';

import React, { useRef, useState } from 'react';
import useSWR from 'swr';
import {
    HardDrive,
    RefreshCw,
    Edit3,
    Search,
    Database,
    X,
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';

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
        // Preserve exact capacity for fractional and sub-GB quotas.
        setQuotaInput(`${quota.quota_bytes}B`);
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
        <div className="space-y-6 w-full animate-fade-in text-slate-100">
            {/* Header Banner */}
            <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 md:p-6 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-indigo-500/10 via-cyan-500/5 to-transparent rounded-full blur-3xl pointer-events-none" />
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shadow-[0_0_24px_rgba(99,102,241,0.3)]">
                            <HardDrive size={24} />
                        </div>
                        <div>
                            <h2 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
                                Storage Quotas
                            </h2>
                            <p className="text-sm text-slate-400">
                                User disk allocation, capacity thresholds, and automated space recalculations.
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center bg-black/40 border border-white/10 p-1 rounded-2xl backdrop-blur-md">
                        <span className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-indigo-500/30 to-cyan-500/20 text-white border border-indigo-500/40 shadow-[0_0_12px_rgba(99,102,241,0.25)] flex items-center gap-2">
                            <Database size={14} /> Disk Quotas ({quotas.length})
                        </span>
                    </div>
                </div>

                {/* Telemetry Summary Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6 pt-6 border-t border-white/10">
                    <div className="bg-black/40 border border-white/5 rounded-2xl p-4">
                        <span className="text-xs text-slate-400 font-medium block">Total Allocated Storage</span>
                        <span className="text-xl font-mono font-bold text-white mt-1 block">
                            {formatBytes(totalAllocatedBytes)}
                        </span>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-2xl p-4">
                        <span className="text-xs text-slate-400 font-medium block">Current Storage Consumption</span>
                        <span className="text-xl font-mono font-bold text-cyan-300 mt-1 block">
                            {formatBytes(totalUsedBytes)}
                        </span>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-2xl p-4">
                        <span className="text-xs text-slate-400 font-medium block">Quota Enforcement Status</span>
                        <div className="flex items-center gap-2 mt-1">
                            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                            <span className="text-sm font-semibold text-emerald-300">
                                {configuredUsersCount} Configured / Active
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Filter Search Bar */}
            <div className="relative">
                <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                    type="text"
                    placeholder="Search users or IDs..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-black/40 border border-white/10 rounded-2xl pl-11 pr-4 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 backdrop-blur-md"
                />
            </div>

            {/* DISK QUOTAS */}
            <div className="space-y-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl overflow-hidden divide-y divide-white/[0.04]">
                    {quotasLoading ? (
                        <div className="p-8 text-center text-slate-400 text-sm flex items-center justify-center gap-3">
                            <RefreshCw size={18} className="animate-spin text-indigo-400" />
                            Loading storage quota records...
                        </div>
                    ) : filteredQuotas.length === 0 ? (
                        <div className="p-12 text-center space-y-3">
                            <Database size={32} className="mx-auto text-slate-600" />
                            <h4 className="text-sm font-semibold text-slate-300">No Quota Records Found</h4>
                            <p className="text-xs text-slate-500 max-w-sm mx-auto">
                                {searchQuery ? 'No users match your search criteria.' : 'No users have disk quotas provisioned.'}
                            </p>
                        </div>
                    ) : (
                        filteredQuotas.map((quota) => {
                            const usagePct = quota.usage_pct ?? (quota.quota_bytes > 0 ? (quota.used_bytes / quota.quota_bytes) * 100 : 0);
                            const isWarning = usagePct >= 80 && usagePct < 95;
                            const isDanger = usagePct >= 95;

                            return (
                                <div
                                    key={quota.user_id}
                                    className="p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors"
                                >
                                    <div className="flex items-center gap-3.5 min-w-[220px]">
                                        <div className="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center text-indigo-400 shrink-0 font-bold font-mono text-xs">
                                            #{quota.user_id}
                                        </div>
                                        <div>
                                            <div className="flex items-center gap-2">
                                                <span className="font-semibold text-white text-sm">
                                                    {quota.username}
                                                </span>
                                                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 bg-white/[0.04] px-2 py-0.5 rounded border border-white/5">
                                                    {quota.source || 'default'}
                                                </span>
                                            </div>
                                            <span className="text-xs text-slate-400 font-mono">
                                                {formatBytes(quota.used_bytes)} / {formatBytes(quota.quota_bytes)}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Progress Bar & Meter */}
                                    <div className="flex-1 max-w-md space-y-1">
                                        <div className="flex items-center justify-between text-xs font-mono">
                                            <span className="text-slate-400">Utilization</span>
                                            <span className={`font-bold ${isDanger ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-cyan-400'}`}>
                                                {usagePct.toFixed(1)}%
                                            </span>
                                        </div>
                                        <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden border border-white/5">
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
                                    <div className="flex items-center gap-2 self-end md:self-center">
                                        <button
                                            type="button"
                                            disabled={refreshingUserId === quota.user_id}
                                            onClick={() => handleRefreshQuota(quota.user_id, quota.username)}
                                            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 hover:text-white border border-white/10 flex items-center gap-1.5 transition-all"
                                            title="Scan disk to recalculate used space"
                                        >
                                            <RefreshCw
                                                size={13}
                                                className={refreshingUserId === quota.user_id ? 'animate-spin text-indigo-400' : 'text-slate-400'}
                                            />
                                            Scan Disk
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => handleOpenEditModal(quota)}
                                            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 hover:text-indigo-200 border border-indigo-500/30 flex items-center gap-1.5 transition-all"
                                        >
                                            <Edit3 size={13} />
                                            Edit Quota
                                        </button>
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>
            </div>

            {/* MODAL: EDIT DISK QUOTA */}
            {selectedQuota && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl w-full max-w-md p-6 shadow-2xl relative animate-fade-in">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-5">
                            <h3 className="text-base font-bold text-white flex items-center gap-2">
                                <Edit3 size={18} className="text-indigo-400" /> Update Disk Quota
                            </h3>
                            <button
                                onClick={() => { quotaDraftRevision.current += 1; setSelectedQuota(null); }}
                                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleSaveQuota} className="space-y-4">
                            <div>
                                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-1">
                                    Target User
                                </label>
                                <div className="p-3 bg-white/[0.03] border border-white/10 rounded-xl text-sm font-semibold text-white flex items-center justify-between">
                                    <span>{selectedQuota.username}</span>
                                    <span className="text-xs font-mono text-slate-400">ID: #{selectedQuota.user_id}</span>
                                </div>
                            </div>

                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Allocated Disk Space
                                </label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. 50GB, 250GB, 1TB"
                                    value={quotaInput}
                                    onChange={(e) => { quotaDraftRevision.current += 1; setQuotaInput(e.target.value); }}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 font-mono"
                                />
                                <span className="text-xs text-slate-500 mt-1 block">
                                    Accepts sizes like 100GB, 500GB, 2TB or exact bytes. Filesystem limits round up to the nearest 1 KiB.
                                </span>
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={() => { quotaDraftRevision.current += 1; setSelectedQuota(null); }}
                                    className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSavingQuota}
                                    className="px-5 py-2 bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                                >
                                    {isSavingQuota ? 'Saving...' : 'Apply Quota'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
