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
import QuotasBillingTab from '@/components/tabs/QuotasBillingTab';

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
        if (!confirm('Are you sure you want to permanently delete this user?')) return;

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
            cell: info => <span className="text-slate-500 font-mono text-xs">#{info.getValue() as number}</span>,
            size: 80,
        },
        {
            id: 'user',
            header: 'User',
            cell: ({ row }) => {
                const user = row.original;
                return (
                    <div className="flex items-center gap-3">
                        {user.avatar_url ? (
                            <Image src={user.avatar_url} alt="" width={32} height={32} className="rounded-full border border-white/10 shrink-0" />
                        ) : (
                            <div className="w-8 h-8 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center shrink-0">
                                <Users size={14} className="text-slate-500" />
                            </div>
                        )}
                        <div>
                            <div className="font-semibold text-slate-100 text-xs">{user.username}</div>
                            <div className="text-[11px] text-slate-500">{user.email}</div>
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
                    <div className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${role === 'admin'
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
                        <div className="flex items-center justify-end gap-1.5 opacity-100 md:opacity-0 md:group-hover:opacity-100 transition-opacity">
                            <button
                                onClick={() => toggleRole(user.id, user.role)}
                                disabled={actionLoading === user.id}
                                title={user.role === 'admin' ? 'Demote to User' : 'Promote to Admin'}
                                className={`p-1.5 rounded-lg border transition-all ${user.role === 'admin'
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
                                className="p-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-all"
                            >
                                <Trash2 size={14} />
                            </button>
                        </div>
                    </RequireClaim>
                );
            },
            size: 150,
        }
    ], [actionLoading]);

    if (isLoading) {
        return <UsersSkeleton />;
    }

    if (error || !users) {
        return (
            <div className="p-6 bg-red-500/10 border border-red-500/20 rounded-2xl text-center max-w-2xl">
                <ShieldAlert className="mx-auto text-red-400 mb-4" size={32} />
                <h3 className="text-lg font-bold text-slate-200">Access Denied</h3>
                <p className="text-sm text-slate-400">You do not have permission to view the user list or the API is offline.</p>
            </div>
        );
    }

    const adminCount = users.filter(u => u.role === 'admin').length;
    const standardUserCount = users.filter(u => u.role !== 'admin').length;

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar with Segmented Navigation */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        <Users size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Identity &amp; Quota Management</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
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
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
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
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                activeSubTab === 'quotas'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <HardDrive size={13} />
                            Storage Quotas &amp; Billing
                        </button>
                    </div>

                    <button
                        type="button"
                        onClick={() => mutate()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Users"
                    >
                        <RefreshCw size={13} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Open Summary Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Users</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{users.length}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Nexus directory accounts</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <Users size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Administrators</p>
                        <p className="text-2xl font-bold text-amber-400 mt-1">{adminCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Full access operator roles</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                        <Shield size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Standard Users</p>
                        <p className="text-2xl font-bold text-emerald-400 mt-1">{standardUserCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Non-privileged accounts</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <UserCheck size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Policy Engine</p>
                        <p className="text-base font-bold text-slate-100 mt-1">RBAC Active</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Strict claim gating enforced</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                        <ShieldAlert size={20} />
                    </div>
                </div>
            </div>

            {/* Sub-tab view */}
            {activeSubTab === 'users' ? (
                <>
                    <DataGrid
                        columns={columns}
                        data={users}
                        className="w-full"
                    />

                    <div className="rounded-2xl border border-blue-500/20 bg-blue-950/20 p-4 flex gap-3 text-xs text-blue-200">
                        <Shield className="text-blue-400 shrink-0 mt-0.5" size={16} />
                        <p className="leading-relaxed">
                            <strong className="text-blue-300">Admin Privileges:</strong> Admins have full access to system configuration, marketplace installations, user management, and service controls. Standard users can monitor metrics and chat with FlowAI, but cannot perform destructive actions.
                        </p>
                    </div>
                </>
            ) : (
                <QuotasBillingTab />
            )}
        </div>
    );
}
