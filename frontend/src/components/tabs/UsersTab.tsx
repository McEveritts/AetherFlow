import { useState } from 'react';
import useSWR from 'swr';
import { useToast } from '@/contexts/ToastContext';
import { User } from '@/contexts/AuthContext';
import { Shield, ShieldAlert, Trash2, Users, Check, X } from 'lucide-react';
import SkeletonBox from '@/components/layout/SkeletonBox';

const fetcher = (url: string) => {
    // Assuming cookies are sent automatically for same-origin if not we would need to pass credentials
    return fetch(url).then((res) => {
        if (!res.ok) throw new Error('API Error');
        return res.json();
    });
};

export default function UsersTab() {
    const { addToast } = useToast();
    const { data: users, error, isLoading, mutate } = useSWR<User[]>('/api/users', fetcher);

    const [actionLoading, setActionLoading] = useState<number | null>(null);

    const toggleRole = async (userId: number, currentRole: string) => {
        const newRole = currentRole === 'admin' ? 'user' : 'admin';
        setActionLoading(userId);

        try {
            const res = await fetch(`/api/users/${userId}/role`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: newRole })
            });

            const data = await res.json();

            if (res.ok) {
                addToast(`User role updated to ${newRole}`, 'success');
                mutate();
            } else {
                addToast(data.error || 'Failed to update role', 'error');
            }
        } catch (err) {
            addToast('Network error updating role.', 'error');
        } finally {
            setActionLoading(null);
        }
    };

    const deleteUser = async (userId: number) => {
        if (!confirm('Are you sure you want to permanently delete this user?')) return;

        setActionLoading(userId);

        try {
            const res = await fetch(`/api/users/${userId}`, {
                method: 'DELETE'
            });

            const data = await res.json();

            if (res.ok) {
                addToast('User deleted successfully', 'success');
                mutate();
            } else {
                addToast(data.error || 'Failed to delete user', 'error');
            }
        } catch (err) {
            addToast('Network error deleting user.', 'error');
        } finally {
            setActionLoading(null);
        }
    };

    if (isLoading) {
        return (
            <div className="space-y-6 animate-fade-in max-w-5xl">
                <div className="flex items-center gap-3">
                    <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl">
                        <Users size={24} />
                    </div>
                    <div>
                        <h2 className="text-2xl font-bold tracking-tight text-white">User Management</h2>
                        <p className="text-sm text-slate-400">Loading user database...</p>
                    </div>
                </div>

                <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl overflow-hidden p-6">
                    <div className="space-y-4">
                        {[1, 2, 3].map(i => (
                            <SkeletonBox key={i} className="h-16 w-full" />
                        ))}
                    </div>
                </div>
            </div>
        );
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

    return (
        <div className="space-y-6 animate-fade-in max-w-5xl pb-10">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="p-3 bg-indigo-500/20 text-indigo-400 rounded-xl shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                        <Users size={24} />
                    </div>
                    <div>
                        <h2 className="text-2xl font-bold tracking-tight text-white">User Management</h2>
                        <p className="text-sm text-slate-400">Manage access roles, permissions, and accounts in the Nexus.</p>
                    </div>
                </div>
                <div className="px-4 py-2 bg-slate-900 rounded-xl border border-white/10 text-sm font-mono text-slate-400">
                    Total Accounts: <span className="text-white font-bold">{users.length}</span>
                </div>
            </div>

            <div className="bg-white/[0.02] backdrop-blur-xl border border-white/[0.05] rounded-3xl overflow-hidden shadow-2xl">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-950/50 border-b border-white/5">
                                <th className="p-4 text-xs font-semibold text-slate-400 uppercase tracking-wider pl-6">ID</th>
                                <th className="p-4 text-xs font-semibold text-slate-400 uppercase tracking-wider">User</th>
                                <th className="p-4 text-xs font-semibold text-slate-400 uppercase tracking-wider">Role</th>
                                <th className="p-4 text-xs font-semibold text-slate-400 uppercase tracking-wider text-right pr-6">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5 text-sm">
                            {users.map((user) => (
                                <tr key={user.id} className="hover:bg-white/[0.02] transition-colors group">
                                    <td className="p-4 pl-6 text-slate-500 font-mono">#{user.id}</td>
                                    <td className="p-4">
                                        <div className="flex items-center gap-3">
                                            {user.avatar_url ? (
                                                <img src={user.avatar_url} alt="" className="w-8 h-8 rounded-full border border-white/10 shrink-0" />
                                            ) : (
                                                <div className="w-8 h-8 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center shrink-0">
                                                    <Users size={14} className="text-slate-500" />
                                                </div>
                                            )}
                                            <div>
                                                <div className="font-semibold text-slate-200">{user.username}</div>
                                                <div className="text-xs text-slate-500">{user.email}</div>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="p-4">
                                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${user.role === 'admin'
                                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                            }`}>
                                            {user.role === 'admin' ? <Shield size={12} /> : <Users size={12} />}
                                            {user.role.toUpperCase()}
                                        </div>
                                    </td>
                                    <td className="p-4 pr-6 text-right">
                                        <div className="flex items-center justify-end gap-2 opacity-100 md:opacity-0 md:group-hover:opacity-100 transition-opacity">
                                            <button
                                                onClick={() => toggleRole(user.id, user.role)}
                                                disabled={actionLoading === user.id}
                                                title={user.role === 'admin' ? 'Demote to User' : 'Promote to Admin'}
                                                className={`p-2 rounded-lg border transition-all ${user.role === 'admin'
                                                        ? 'bg-slate-900 border-white/10 text-slate-400 hover:text-white hover:bg-slate-800'
                                                        : 'bg-indigo-500/10 border-indigo-500/20 text-indigo-400 hover:bg-indigo-500/20 hover:text-indigo-300'
                                                    }`}
                                            >
                                                {user.role === 'admin' ? <X size={16} /> : <Check size={16} />}
                                            </button>

                                            <button
                                                onClick={() => deleteUser(user.id)}
                                                disabled={actionLoading === user.id}
                                                title="Delete User"
                                                className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-all"
                                            >
                                                <Trash2 size={16} />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/20 rounded-2xl p-4 flex gap-3 text-sm text-blue-200">
                <Shield className="text-blue-400 shrink-0 mt-0.5" size={18} />
                <p>
                    <strong className="text-blue-300">Admin Privileges:</strong> Admins have full access to system configuration, marketplace installations, user management, and service controls. Standard users can monitor metrics and chat with FlowAI, but cannot perform destructive actions.
                </p>
            </div>
        </div>
    );
}
