import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { UserCircle, Mail, AlertCircle, Save, HardDrive } from 'lucide-react';
import { useState, useEffect } from 'react';
import useSWR from 'swr';
import SkeletonBox from '@/components/layout/SkeletonBox';
import Image from 'next/image';

const fetcher = (url: string) => fetch(url).then(r => r.json());

export default function ProfileTab() {
    const { user } = useAuth();
    const { addToast } = useToast();
    const [email, setEmail] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    const { data: quota, isLoading: isQuotaLoading } = useSWR(
        user ? `/api/user/quota/${user.id}` : null,
        fetcher
    );

    useEffect(() => {
        if (user) setEmail(user.email);
    }, [user]);

    const handleUpdate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSaving(true);

        try {
            const res = await fetch('/api/auth/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
                credentials: 'include'
            });

            const data = await res.json();
            if (res.ok) {
                addToast('Profile updated. Please log out and back in to sync your active session cache.', 'success');
            } else {
                addToast(data.error || 'Failed to update profile', 'error');
            }
        } catch (_err) {
            addToast('Network error updating profile', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    if (!user) {
        return (
            <div className="flex items-center justify-center min-h-[50vh] text-slate-400">
                Loading secure user context...
            </div>
        );
    }

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-[calc(100vh-10rem)]">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden">
                <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-purple-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/2"></div>

                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <UserCircle size={24} className="text-purple-400" />
                    User Profile
                </h2>

                <div className="max-w-2xl relative z-10">
                    <div className="flex items-start gap-8 mb-10 pb-10 border-b border-white/5">
                        <Image
                            src={user.avatar_url || 'https://via.placeholder.com/150'}
                            alt="Profile Avatar"
                            width={96}
                            height={96}
                            className="rounded-2xl shadow-lg border border-white/10"
                        />
                        <div>
                            <h3 className="text-2xl font-bold text-slate-200">{user.username}</h3>
                            <div className="flex items-center gap-2 mt-2">
                                <span className="bg-purple-500/10 text-purple-400 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest border border-purple-500/20">
                                    {user.role}
                                </span>
                                <span className="text-slate-500 text-sm">OAuth Connected</span>
                            </div>
                        </div>
                    </div>

                    <form onSubmit={handleUpdate} className="space-y-8">
                        <div>
                            <label className="block text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
                                <Mail size={16} className="text-slate-400" /> Notification Email
                            </label>
                            <input
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-purple-500/50 transition-colors"
                            />
                            <p className="text-xs text-slate-500 mt-2">Where AetherFlow sends critical system alerts.</p>
                        </div>

                        <div className="pt-4 flex items-center gap-4">
                            <button
                                type="submit"
                                disabled={isSaving || email === user.email}
                                className="px-8 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-600/50 rounded-xl text-sm font-bold text-white transition-all shadow-lg shadow-purple-500/20 flex items-center gap-2"
                            >
                                <Save size={18} />
                                {isSaving ? 'Saving...' : 'Update Details'}
                            </button>
                        </div>
                    </form>

                    {/* Account Storage Quota */}
                    <div className="mt-12 bg-white/[0.02] border border-white/[0.05] rounded-2xl p-8 backdrop-blur-md">
                        <div className="flex items-center gap-3 mb-6">
                            <div className="p-3 bg-indigo-500/20 text-indigo-400 rounded-xl">
                                <HardDrive size={24} />
                            </div>
                            <div>
                                <h3 className="text-xl font-bold text-slate-200">Account Storage Quotas</h3>
                                <p className="text-sm text-slate-400">Your total disk boundaries within the Nexus filesystem.</p>
                            </div>
                        </div>

                        {isQuotaLoading ? (
                            <div className="space-y-4">
                                <SkeletonBox className="h-4 w-full" />
                                <SkeletonBox className="h-10 w-full" />
                            </div>
                        ) : quota ? (
                            <div className="space-y-4">
                                <div className="flex items-end justify-between text-sm">
                                    <span className="font-semibold text-slate-300">Space Used</span>
                                    <div className="text-right">
                                        <span className="text-xl font-bold text-white">{quota.usedGB.toFixed(1)} GB</span>
                                        <span className="text-slate-500"> / {quota.totalGB} GB</span>
                                    </div>
                                </div>
                                <div className="h-4 w-full bg-slate-900 border border-white/10 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full transition-all duration-1000 flex items-center justify-end px-2 text-[10px] font-bold ${quota.percentage > 90 ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' :
                                            quota.percentage > 75 ? 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]' :
                                                'bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.5)]'
                                            }`}
                                        style={{ width: `${Math.min(quota.percentage, 100)}%` }}
                                    ></div>
                                </div>
                                <p className="text-xs text-slate-500 text-right mt-2">{quota.percentage.toFixed(1)}% utilized</p>
                            </div>
                        ) : (
                            <div className="p-4 border border-red-500/20 bg-red-500/10 text-red-400 rounded-xl text-sm">
                                Failed to fetch storage quotas.
                            </div>
                        )}
                    </div>

                    <div className="mt-12 bg-red-500/5 border border-red-500/20 rounded-2xl p-6">
                        <div className="flex gap-4">
                            <AlertCircle className="text-red-400 shrink-0" size={24} />
                            <div>
                                <h3 className="text-lg font-bold text-slate-200 mb-2">Danger Zone</h3>
                                <p className="text-sm text-slate-400 mb-4">You are currently logged in via Google OAuth. To delete this account, revoke access from your Google Account settings, which will lock you out of this dashboard.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
