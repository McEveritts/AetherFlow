import { useState, useMemo } from 'react';
import useSWR from 'swr';
import { useToast } from '@/contexts/ToastContext';
import { User } from '@/contexts/AuthContext';
import { Shield, ShieldAlert, Trash2, Users, Check, X, HardDrive, RefreshCw, UserCheck } from 'lucide-react';
import { UsersSkeleton } from '@/components/layout/SkeletonBox';
import Image from 'next/image';
import { DataGrid } from '@/components/ui/DataGrid';
import { ColumnDef } from '@tanstack/react-table';
import { apiFetch } from '@/lib/fetcher';
import RequireClaim from '@/components/auth/RequireClaim';
import QuotasTab from '@/components/tabs/QuotasTab';
import ResponsiveSummary from '@/components/ui/ResponsiveSummary';

export default function UsersTab() {
    const { addToast } = useToast();
    const [activeSubTab, setActiveSubTab] = useState<'users' | 'quotas'>('users');
    const { data: users, error, isLoading, isValidating, mutate } = useSWR<User[]>('/api/v1/admin/users');

    const [actionLoading, setActionLoading] = useState<number | null>(null);

    const toggleRole = async (userId: number, currentRole: string) => {
        const newRole = currentRole === 'admin' ? 'user' : 'admin';
        setActionLoading(userId);

        const optimisticData = users ? users.map(u => u.id === userId ? { ...u, role: newRole } : u) : [];
        if (users) {
            mutate(optimisticData, false);
        }

        try {
            const res = await apiFetch(`/api/v1/admin/users/${userId}/role`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: newRole })
            });

            const data = await res.json();

            if (res.ok) {
                addToast(`User role updated to ${newRole}`, 'success');
                mutate();
            } else {
                mutate(users, false);
                addToast(data.error || 'Role enforcement denied', 'error');
            }
        } catch (_err) {
            mutate(users, false);
            addToast('API dispatch failure: Role enforcement.', 'error');
        } finally {
            setActionLoading(null);
        }
    };

    const deleteUser = async (userId: number) => {
        const targetUser = users?.find(user => user.id === userId);
        if (!targetUser) return;
        const targetIdentity = targetUser.email ? `${targetUser.username} (${targetUser.email})` : `${targetUser.username} (ID ${targetUser.id})`;
        if (!confirm(`Permanently delete ${targetIdentity}? This cannot be undone.`)) return;

        setActionLoading(userId);

        const optimisticData = users ? users.filter(u => u.id !== userId) : [];
        if (users) {
            mutate(optimisticData, false);
        }

        try {
            const res = await apiFetch(`/api/v1/admin/users/${userId}`, {
                method: 'DELETE'
            });

            const data = await res.json();

            if (res.ok) {
                addToast('User deleted successfully', 'success');
                mutate();
            } else {
                mutate(users, false);
                addToast(data.error || 'User purge sequence denied', 'error');
            }
        } catch (_err) {
            mutate(users, false);
            addToast('API dispatch failure: User purge.', 'error');
        } finally {
            setActionLoading(null);
        }
    };

    const columns = useMemo<ColumnDef<User>[]>(() => [
        {
            accessorKey: 'id',
            header: 'ID',
            cell: info => <span className="text-slate-400 font-mono text-xs">#{info.getValue() as number}</span>,
            size: 80,
        },
        {
            id: 'user',
            header: 'User',
            cell: ({ row }) => {
                const user = row.original;
                return (
                    <div className="flex items-center gap-3 min-w-0">
                        {user.avatar_url ? (
                            <Image src={user.avatar_url} alt="" width={32} height={32} className="rounded-full border border-white/10 shrink-0" />
                        ) : (
                            <div className="w-8 h-8 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center shrink-0">
                                <Users size={14} className="text-slate-400" />
                            </div>
                        )}
                        <div className="min-w-0 break-words [overflow-wrap:anywhere]">
                            <div className="font-semibold text-slate-100 text-sm">{user.username}</div>
                            <div className="text-xs text-slate-400">{user.email}</div>
                        </div>
                    </div>
                );
            },
        },
        {
            accessorKey: 'role',
            header: 'Role',
            cell: info => {
                const role = info.getValue() as string;
                return (
                    <div className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${role === 'admin'
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        }`}>
                        {role === 'admin' ? <Shield size={11} /> : <Users size={11} />}
                        {role.toUpperCase()}
                    </div>
                );
            },
        },
        {
            id: 'actions',
            header: () => <div className="text-right w-full">Actions</div>,
            cell: ({ row }) => {
                const user = row.original;
                return (
                    <RequireClaim>
                        <div className="flex items-center justify-end gap-1.5">
                            <button
                                onClick={() => toggleRole(user.id, user.role)}
                                disabled={actionLoading === user.id}
                                title={user.role === 'admin' ? 'Demote to User' : 'Promote to Admin'}
                                aria-label={`${user.role === 'admin' ? 'Demote to User' : 'Promote to Admin'} ${user.username}`}
                                className={`obs-touch-target-standard p-2 rounded-lg border transition-all min-h-[44px] min-w-[44px] flex items-center justify-center focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400 ${user.role === 'admin'
                                    ? 'bg-slate-900 border-white/10 text-slate-400 hover:text-white hover:bg-slate-800'
                                    : 'bg-indigo-500/10 border-indigo-500/20 text-indigo-400 hover:bg-indigo-500/20 hover:text-indigo-300'
                                    }`}
                            >
                                {user.role === 'admin' ? <X size={14} /> : <Check size={14} />}
                            </button>

                            <button
                                onClick={() => deleteUser(user.id)}
                                disabled={actionLoading === user.id}
                                title="Delete User"
                                aria-label={`Delete User ${user.username}`}
                                className="obs-touch-target-standard p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 hover:text-rose-300 transition-all min-h-[44px] min-w-[44px] flex items-center justify-center focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-rose-400"
                            >
                                <Trash2 size={14} />
                            </button>
                        </div>
                    </RequireClaim>
                );
            },
            size: 150,
        }
    ], [actionLoading, users]);

    if (isLoading) {
        return <UsersSkeleton />;
    }

    if (error || !users) {
        return (
            <div role="status" className="p-8 border-b border-rose-500/25 bg-rose-500/[0.06] text-center min-w-0">
                <ShieldAlert className="mx-auto text-rose-400 mb-3" size={32} />
                <h3 className="text-base font-bold text-slate-100">Access Denied</h3>
                <p className="text-xs text-slate-400 mt-1">You do not have permission to view the user list or the API is offline.</p>
            </div>
        );
    }

    const adminCount = users.filter(u => u.role === 'admin').length;
    const standardUserCount = users.filter(u => u.role !== 'admin').length;

    return (
        <div className="animate-fade-in relative z-10 w-full min-w-0 pb-10">
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-white/[0.07] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400 shrink-0">
                        <Users size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Identity &amp; Quota Management</h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                RBAC Enforced
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Nexus Directory &middot; {users.length} registered accounts
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    {/* Segmented Pill Switcher */}
                    <div className="flex items-center gap-1 p-1 bg-white/[0.04] border border-white/10 rounded-xl">
                        <button
                            type="button"
                            onClick={() => setActiveSubTab('users')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 min-h-[36px] ${
                                activeSubTab === 'users'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Users size={13} />
                            Directory ({users.length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveSubTab('quotas')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 min-h-[36px] ${
                                activeSubTab === 'quotas'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <HardDrive size={13} />
                            Storage Quotas
                        </button>
                    </div>

                    {activeSubTab === 'users' && (
                        <button
                            type="button"
                            onClick={() => mutate()}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all min-h-[36px]"
                            title="Refresh Users"
                        >
                            <RefreshCw size={13} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                            <span>Refresh</span>
                        </button>
                    )}
                </div>
            </div>

            <ResponsiveSummary label={`Directory summary · ${users.length} accounts`}>
                <div className="obs-metric-strip">
                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div>
                            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Users</p>
                            <p className="text-2xl font-bold text-slate-100 mt-1">{users.length}</p>
                            <p className="text-xs text-slate-400 mt-0.5">Nexus directory accounts</p>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                            <Users size={20} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div>
                            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Administrators</p>
                            <p className="text-2xl font-bold text-amber-400 mt-1">{adminCount}</p>
                            <p className="text-xs text-slate-400 mt-0.5">Full access operator roles</p>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                            <Shield size={20} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div>
                            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Standard Users</p>
                            <p className="text-2xl font-bold text-emerald-400 mt-1">{standardUserCount}</p>
                            <p className="text-xs text-slate-400 mt-0.5">Non-privileged accounts</p>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                            <UserCheck size={20} />
                        </div>
                    </div>

                    <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                        <div>
                            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Policy Engine</p>
                            <p className="text-base font-bold text-slate-100 mt-1">RBAC Active</p>
                            <p className="text-xs text-slate-400 mt-0.5">Strict claim gating enforced</p>
                        </div>
                        <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                            <ShieldAlert size={20} />
                        </div>
                    </div>
                </div>
            </ResponsiveSummary>

            {/* Sub-tab view */}
            {activeSubTab === 'users' ? (
                <div className="min-w-0 space-y-4">
                    <DataGrid
                        columns={columns}
                        data={users}
                        responsiveRows={{ primaryColumnId: 'user', actionsColumnId: 'actions' }}
                        className="w-full border-b border-white/[0.07]"
                    />

                    <div className="border-b border-blue-500/25 bg-blue-500/[0.06] p-4 flex gap-3 text-xs text-blue-200 min-w-0">
                        <Shield className="text-blue-400 shrink-0 mt-0.5" size={16} />
                        <p className="leading-relaxed">
                            <strong className="text-blue-300">Admin Privileges:</strong> Admins have full access to system configuration, marketplace installations, user management, and service controls. Standard users can monitor metrics and chat with FlowAI, but cannot perform destructive actions.
                        </p>
                    </div>
                </div>
            ) : (
                <QuotasTab />
            )}
        </div>
    );
}
