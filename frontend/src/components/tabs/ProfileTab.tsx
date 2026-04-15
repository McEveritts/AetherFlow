import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { UserCircle, Mail, AlertCircle, Save, HardDrive } from 'lucide-react';
import { useState, useEffect } from 'react';
import useSWR from 'swr';
import SkeletonBox from '@/components/layout/SkeletonBox';
import Image from 'next/image';
import { apiFetch } from '@/lib/fetcher';

export default function ProfileTab() {
    const { user } = useAuth();
    const { addToast } = useToast();
    const [email, setEmail] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    const { data: quota, isLoading: isQuotaLoading } = useSWR(
        user ? `/api/v1/auth/user/quota` : null
    );

    useEffect(() => {
        if (user) setEmail(user.email);
    }, [user]);

    const handleUpdate = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSaving(true);

        try {
            const res = await apiFetch('/api/v1/auth/profile', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });

            const data = await res.json();
            if (res.ok) {
                addToast('Profile updated. Please log out and back in to sync your active session cache.', 'success');
            } else {
                addToast(data.error || 'Profile state mutation rejected.', 'error');
            }
        } catch (_err) {
            addToast('API dispatch failure: Profile state mutation.', 'error');
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
        <div className="space-y-8 animate-fade-in relative z-10 w-full mb-8">
            <h3 className="text-xl font-bold text-slate-100 flex items-center gap-3 border-b border-white/5 pb-4">
                <UserCircle size={24} className="text-indigo-400" />
                Local Profile
            </h3>

            <div className="max-w-2xl relative z-10 space-y-10">
                {/* Avatar & Basics */}
                <div className="flex flex-col md:flex-row items-center md:items-start gap-8 pb-10 border-b border-white/5">
                    <div className="flex flex-col items-center gap-4">
                        <div className="relative group">
                            <Image
                                src={user.avatar_url || 'https://via.placeholder.com/150'}
                                alt="Profile Avatar"
                                width={112}
                                height={112}
                                className="rounded-2xl shadow-lg border border-white/10"
                            />
                            <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl flex items-center justify-center backdrop-blur-sm cursor-pointer">
                                <span className="text-xs font-bold text-white uppercase tracking-wider">Change</span>
                            </div>
                        </div>
                        <button type="button" className="text-xs text-slate-400 hover:text-indigo-400 transition-colors">
                            Remove Avatar
                        </button>
                    </div>
                    
                    <div className="text-center md:text-left flex-1">
                        <h3 className="text-3xl font-bold text-slate-100 tracking-tight">{user.username}</h3>
                        <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 mt-3">
                            <span className="bg-indigo-500/10 text-indigo-400 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest border border-indigo-500/20">
                                {user.role}
                            </span>
                            <span className={`text-xs font-bold px-3 py-1 rounded-full border ${user.is_oauth ? 'bg-amber-500/10 text-amber-500/80 border-amber-500/20' : 'bg-slate-800 text-slate-400 border-white/5'}`}>
                                {user.is_oauth ? 'OAuth Connected' : 'Local Account'}
                            </span>
                        </div>
                        {user.is_oauth && (
                            <div className="mt-4 flex gap-3 text-sm text-amber-500/80 bg-amber-500/5 p-4 rounded-xl border border-amber-500/10 text-left">
                                <AlertCircle size={20} className="shrink-0" />
                                <p>You are logged in via Google OAuth. To delete this account, revoke access from your Google Account settings.</p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Email Management */}
                <form onSubmit={handleUpdate} className="space-y-6">
                    <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Email Preferences</h4>
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <label className="block text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                            <Mail size={16} className="text-slate-400" /> Notification Email
                        </label>
                        <div className="flex flex-col md:flex-row gap-4">
                            <input
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="flex-1 bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors"
                            />
                            <button
                                type="submit"
                                disabled={isSaving || email === user.email}
                                className="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/30 disabled:text-slate-500 rounded-xl text-sm font-bold text-white transition-all whitespace-nowrap"
                            >
                                {isSaving ? 'Saving...' : 'Update Email'}
                            </button>
                        </div>
                        <p className="text-xs text-slate-500 mt-3">Where AetherFlow sends critical system alerts and authentication events.</p>
                    </div>
                </form>

                {/* Security Section (Mockup) */}
                <div className="space-y-6">
                    <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Authentication & Security</h4>
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                        
                        <div className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div>
                                <h5 className="text-sm font-semibold text-slate-200">Account Password</h5>
                                <p className="text-xs text-slate-500 mt-1">Change the password used to access your local account.</p>
                            </div>
                            <button type="button" className="px-6 py-2.5 bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-sm font-bold rounded-xl transition-colors whitespace-nowrap">
                                Change Password
                            </button>
                        </div>
                        
                        <div className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/30">
                            <div>
                                <h5 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                    Two-Factor Authentication <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-amber-500/20 text-amber-400 border border-amber-500/20">Coming Soon</span>
                                </h5>
                                <p className="text-xs text-slate-500 mt-1">Add an extra layer of security to your account.</p>
                            </div>
                            <button type="button" disabled className="px-6 py-2.5 bg-transparent border border-white/5 text-slate-500 text-sm font-bold rounded-xl transition-colors whitespace-nowrap cursor-not-allowed">
                                Enable 2FA
                            </button>
                        </div>

                    </div>
                </div>

                {/* Account Storage Quota */}
                <div className="space-y-6">
                    <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Quotas & Limits</h4>
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-6">
                            <div className="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-xl">
                                <HardDrive size={20} />
                            </div>
                            <div>
                                <h3 className="font-bold text-slate-200">Account Storage</h3>
                                <p className="text-xs text-slate-400 mt-0.5">Your total disk boundaries within the Nexus filesystem.</p>
                            </div>
                        </div>

                        {isQuotaLoading ? (
                            <div className="space-y-4">
                                <SkeletonBox className="h-4 w-full" />
                                <SkeletonBox className="h-10 w-full" />
                            </div>
                        ) : quota ? (
                            <div className="space-y-3">
                                <div className="flex items-end justify-between text-sm">
                                    <span className="font-semibold text-slate-400">Space Used</span>
                                    <div className="text-right">
                                        <span className="text-lg font-bold text-white">{(quota.usedGB || 0).toFixed(1)} GB</span>
                                        {quota.totalGB > 0 ? (
                                            <span className="text-slate-500 text-xs ml-1">/ {quota.totalGB} GB</span>
                                        ) : (
                                            <span className="text-slate-500 text-[10px] ml-1 uppercase">(No Limit Set)</span>
                                        )}
                                    </div>
                                </div>
                                <div className="h-3 w-full bg-slate-900 border border-white/5 rounded-full overflow-hidden shrink-0">
                                    <div
                                        className={`h-full transition-all duration-1000 ${quota.percentage > 90 ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' :
                                            quota.percentage > 75 ? 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]' :
                                                'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]'
                                            }`}
                                        style={{ width: `${Math.min(quota.percentage || 0, 100)}%` }}
                                    ></div>
                                </div>
                                {quota.totalGB > 0 && (
                                    <p className="text-[11px] text-slate-500 text-right mt-1">{(quota.percentage || 0).toFixed(1)}% utilized</p>
                                )}
                            </div>
                        ) : (
                            <div className="p-4 border border-red-500/20 bg-red-500/10 text-red-400 rounded-xl text-sm">
                                Quota telemetry unavailable.
                            </div>
                        )}
                    </div>
                </div>

            </div>
        </div>
    );
}
