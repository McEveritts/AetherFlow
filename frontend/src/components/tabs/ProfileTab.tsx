import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { Mail, AlertCircle, Save, HardDrive, KeyRound, Lock, X, Loader2 } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import useSWR from 'swr';
import SkeletonBox from '@/components/layout/SkeletonBox';
import Image from 'next/image';
import { apiFetch } from '@/lib/fetcher';

export default function ProfileTab() {
    const { user, refreshSession } = useAuth();
    const { addToast } = useToast();
    const [email, setEmail] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    // Avatar state
    const avatarInputRef = useRef<HTMLInputElement>(null);
    const [isAvatarUpdating, setIsAvatarUpdating] = useState(false);

    // Password modal state
    const [showPasswordModal, setShowPasswordModal] = useState(false);
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [isChangingPassword, setIsChangingPassword] = useState(false);

    const { data: quota, isLoading: isQuotaLoading } = useSWR(
        user ? `/api/v1/auth/user/quota` : null
    );

    useEffect(() => {
        if (user) setEmail(user.email);
    }, [user]);

    const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        if (!file.type.startsWith('image/')) {
            addToast('Selected file must be an image', 'error');
            return;
        }
        if (file.size > 2 * 1024 * 1024) {
            addToast('Avatar image must be under 2MB', 'error');
            return;
        }

        const reader = new FileReader();
        reader.onload = async () => {
            const base64Data = reader.result as string;
            setIsAvatarUpdating(true);
            try {
                const res = await apiFetch('/api/v1/auth/profile/avatar', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ avatar: base64Data })
                });
                const data = await res.json();
                if (res.ok) {
                    await refreshSession();
                    addToast('Avatar updated successfully.', 'success');
                } else {
                    addToast(data.error || 'Failed to update avatar.', 'error');
                }
            } catch {
                addToast('Network error while updating avatar.', 'error');
            } finally {
                setIsAvatarUpdating(false);
                if (avatarInputRef.current) avatarInputRef.current.value = '';
            }
        };
        reader.readAsDataURL(file);
    };

    const handleRemoveAvatar = async () => {
        setIsAvatarUpdating(true);
        try {
            const res = await apiFetch('/api/v1/auth/profile/avatar', {
                method: 'DELETE'
            });
            if (res.ok) {
                await refreshSession();
                addToast('Avatar removed successfully.', 'success');
            } else {
                const data = await res.json().catch(() => ({}));
                addToast(data.error || 'Failed to remove avatar.', 'error');
            }
        } catch {
            addToast('Network error while removing avatar.', 'error');
        } finally {
            setIsAvatarUpdating(false);
        }
    };

    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setPasswordError('');

        if (!currentPassword) {
            setPasswordError('Current password is required');
            return;
        }
        if (newPassword.length < 8) {
            setPasswordError('New password must be at least 8 characters long');
            return;
        }
        if (newPassword !== confirmPassword) {
            setPasswordError('New passwords do not match');
            return;
        }

        setIsChangingPassword(true);
        try {
            const res = await apiFetch('/api/v1/auth/profile/password', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });
            const data = await res.json();
            if (res.ok) {
                addToast('Password changed successfully.', 'success');
                setShowPasswordModal(false);
                setCurrentPassword('');
                setNewPassword('');
                setConfirmPassword('');
            } else {
                setPasswordError(data.error || 'Password update failed');
            }
        } catch {
            setPasswordError('Network error while updating password');
        } finally {
            setIsChangingPassword(false);
        }
    };

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
                await refreshSession();
                addToast('Profile updated successfully.', 'success');
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
        <div className="space-y-6 animate-fade-in relative z-10 w-full mb-8">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 w-full relative z-10">
                {/* LEFT COLUMN: Account Overview & Email Preferences */}
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-6 flex flex-col justify-between space-y-8">
                    {/* Avatar & Basics */}
                    <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 pb-6 border-b border-white/[0.06]">
                        <div className="flex flex-col items-center gap-3 shrink-0">
                            <input
                                type="file"
                                ref={avatarInputRef}
                                accept="image/*"
                                onChange={handleAvatarChange}
                                className="hidden"
                            />
                            <div 
                                className="relative group cursor-pointer"
                                onClick={() => avatarInputRef.current?.click()}
                            >
                                <Image
                                    src={user.avatar_url || 'https://via.placeholder.com/150'}
                                    alt="Profile Avatar"
                                    width={96}
                                    height={96}
                                    className="rounded-2xl shadow-lg border border-white/10 object-cover"
                                />
                                <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl flex items-center justify-center backdrop-blur-sm">
                                    <span className="text-xs font-bold text-white uppercase tracking-wider">
                                        {isAvatarUpdating ? 'Saving...' : 'Change'}
                                    </span>
                                </div>
                            </div>
                            <button 
                                type="button" 
                                onClick={handleRemoveAvatar}
                                disabled={isAvatarUpdating || !user.avatar_url}
                                className="text-xs text-slate-400 hover:text-red-400 disabled:opacity-40 transition-colors"
                            >
                                Remove Avatar
                            </button>
                        </div>
                        
                        <div className="text-center sm:text-left flex-1">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">Account Identity</span>
                            <h3 className="text-2xl font-bold text-slate-100 tracking-tight mt-0.5">{user.username}</h3>
                            <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2 mt-3">
                                <span className="bg-indigo-500/10 text-indigo-400 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-widest border border-indigo-500/20">
                                    {user.role}
                                </span>
                                <span className={`text-xs font-bold px-3 py-1 rounded-full border ${user.is_oauth ? 'bg-amber-500/10 text-amber-500/80 border-amber-500/20' : 'bg-slate-800 text-slate-400 border-white/5'}`}>
                                    {user.is_oauth ? 'OAuth Connected' : 'Local Account'}
                                </span>
                            </div>
                            {user.is_oauth && (
                                <div className="mt-4 flex gap-3 text-xs text-amber-400/90 bg-amber-500/5 p-3.5 rounded-xl border border-amber-500/15 text-left">
                                    <AlertCircle size={18} className="shrink-0 mt-0.5" />
                                    <p>You are logged in via Google OAuth. To delete this account, revoke access from your Google Account settings.</p>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Email Management */}
                    <form onSubmit={handleUpdate} className="space-y-4">
                        <div className="flex items-center justify-between">
                            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Email Preferences</h4>
                            <span className="text-[10px] font-mono uppercase text-slate-500">System Alerts</span>
                        </div>
                        <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-3">
                            <label className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                                <Mail size={15} className="text-indigo-400" /> Notification Email
                            </label>
                            <div className="flex flex-col sm:flex-row gap-3">
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="flex-1 bg-slate-900 border border-white/10 rounded-xl px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors"
                                />
                                <button
                                    type="submit"
                                    disabled={isSaving || email === user.email}
                                    className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/30 disabled:text-slate-500 rounded-xl text-xs font-bold text-white transition-all whitespace-nowrap"
                                >
                                    {isSaving ? 'Saving...' : 'Update Email'}
                                </button>
                            </div>
                            <p className="text-xs text-slate-500">Where AetherFlow sends critical system alerts and authentication events.</p>
                        </div>
                    </form>
                </div>

                {/* RIGHT COLUMN: Authentication & Security + Storage Quota */}
                <div className="space-y-6">
                    {/* Security Section */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-6 space-y-4">
                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
                            <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                                <KeyRound size={16} className="text-indigo-400" /> Authentication & Security
                            </h4>
                        </div>
                        <div className="rounded-xl bg-slate-950/50 border border-white/[0.06] divide-y divide-white/[0.06] overflow-hidden">
                            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                <div>
                                    <h5 className="text-sm font-semibold text-slate-200">Account Password</h5>
                                    <p className="text-xs text-slate-500 mt-0.5">Change the password used to access your local account.</p>
                                </div>
                                <button 
                                    type="button" 
                                    onClick={() => setShowPasswordModal(true)}
                                    className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 text-slate-200 text-xs font-bold rounded-xl transition-colors whitespace-nowrap"
                                >
                                    Change Password
                                </button>
                            </div>
                            
                            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                <div>
                                    <h5 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                        Two-Factor Authentication
                                        {user.totp_enabled ? (
                                            <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/20">Active</span>
                                        ) : (
                                            <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-700/50 text-slate-400 border border-white/10">Inactive</span>
                                        )}
                                    </h5>
                                    <p className="text-xs text-slate-500 mt-0.5">
                                        {user.totp_enabled
                                            ? 'Your account is protected with TOTP-based verification.'
                                            : 'Add an extra layer of security via the Security tab.'}
                                    </p>
                                </div>
                                <span className={`px-4 py-2 text-xs font-bold rounded-xl transition-colors whitespace-nowrap ${
                                    user.totp_enabled
                                        ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                                        : 'bg-white/5 border border-white/10 text-slate-400'
                                }`}>
                                    {user.totp_enabled ? 'Enrolled' : 'Not Enrolled'}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* Account Storage Quota */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-6 space-y-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2.5 bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 rounded-xl">
                                <HardDrive size={18} />
                            </div>
                            <div>
                                <h3 className="text-sm font-bold text-slate-100">Account Storage Quota</h3>
                                <p className="text-xs text-slate-400 mt-0.5">Your disk boundaries within the Nexus filesystem.</p>
                            </div>
                        </div>

                        {isQuotaLoading ? (
                            <div className="space-y-3">
                                <SkeletonBox className="h-4 w-full" />
                                <SkeletonBox className="h-8 w-full" />
                            </div>
                        ) : quota ? (
                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-3">
                                <div className="flex items-end justify-between text-sm">
                                    <span className="text-xs font-semibold text-slate-400">Space Used</span>
                                    <div className="text-right">
                                        <span className="text-base font-bold text-white">{(quota.usedGB || 0).toFixed(1)} GB</span>
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
                            <div className="p-4 border border-red-500/20 bg-red-500/10 text-red-400 rounded-xl text-xs">
                                Quota telemetry unavailable.
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Change Password Modal */}
            {showPasswordModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
                    <div className="w-full max-w-md rounded-2xl p-6 border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl shadow-2xl relative">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
                            <div className="flex items-center gap-2">
                                <Lock className="text-indigo-400" size={20} />
                                <h3 className="text-lg font-bold text-white">Change Password</h3>
                            </div>
                            <button
                                onClick={() => setShowPasswordModal(false)}
                                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        {passwordError && (
                            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-xl flex items-center gap-2">
                                <AlertCircle size={16} className="shrink-0" />
                                <span>{passwordError}</span>
                            </div>
                        )}

                        <form onSubmit={handlePasswordSubmit} className="space-y-4">
                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Current Password</label>
                                <input
                                    type="password"
                                    value={currentPassword}
                                    onChange={(e) => setCurrentPassword(e.target.value)}
                                    placeholder="Enter current password"
                                    required
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1.5">New Password (min 8 chars)</label>
                                <input
                                    type="password"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    placeholder="Enter new secure password"
                                    required
                                    minLength={8}
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Confirm New Password</label>
                                <input
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Confirm new password"
                                    required
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div className="flex justify-end gap-3 pt-4 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={() => setShowPasswordModal(false)}
                                    className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isChangingPassword}
                                    className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white rounded-xl transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                                >
                                    {isChangingPassword ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                                    {isChangingPassword ? 'Updating...' : 'Save Password'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
