import { Shield, Lock, KeyRound, MonitorSmartphone, Laptop, XCircle, ShieldCheck, ShieldOff, Copy, Check, Loader2 } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { apiFetch } from '@/lib/fetcher';
import { QRCodeSVG } from 'qrcode.react';
import useSWR from 'swr';
import { useState, useCallback } from 'react';

interface SessionInfo {
    jti: string;
    ip_address: string;
    user_agent: string;
    expires_at: string;
    last_active: string;
    is_current: boolean;
}

interface SetupResponse {
    otpauth_uri: string;
    secret: string;
}

export default function SecurityTab() {
    const { addToast } = useToast();
    const { user } = useAuth();
    const { data: sessionData, mutate } = useSWR<{ sessions: SessionInfo[] }>('/api/v1/auth/sessions', {
        refreshInterval: 10000,
    });

    const sessions = sessionData?.sessions || [];

    // ── 2FA State ──
    const [setupData, setSetupData] = useState<SetupResponse | null>(null);
    const [isSettingUp, setIsSettingUp] = useState(false);
    const [verifyCode, setVerifyCode] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [disableCode, setDisableCode] = useState('');
    const [isDisabling, setIsDisabling] = useState(false);
    const [showDisableConfirm, setShowDisableConfirm] = useState(false);
    const [secretCopied, setSecretCopied] = useState(false);

    const is2FAEnabled = user?.totp_enabled ?? false;

    // ── Session Actions ──
    const revokeSession = async (jti: string) => {
        try {
            const res = await fetch(`/api/v1/auth/sessions/${encodeURIComponent(jti)}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Failed to revoke session');
            mutate();
            addToast('Session forcefully terminated.', 'success');
        } catch {
            addToast('Error revoking session.', 'error');
        }
    };

    const revokeAllOthers = async () => {
        try {
            const others = sessions.filter(s => !s.is_current);
            await Promise.all(
                others.map(s => fetch(`/api/v1/auth/sessions/${encodeURIComponent(s.jti)}`, { method: 'DELETE' }))
            );
            mutate();
            addToast('All unauthorized sessions revoked.', 'info');
        } catch {
            addToast('Error revoking some sessions.', 'error');
        }
    };

    // ── 2FA Actions ──
    const initSetup = useCallback(async () => {
        setIsSettingUp(true);
        try {
            const res = await apiFetch('/api/v1/auth/user/2fa/setup');
            if (!res.ok) {
                const data = await res.json();
                addToast(data.message || data.error || 'Failed to initiate 2FA setup.', 'error');
                return;
            }
            const data: SetupResponse = await res.json();
            setSetupData(data);
            setVerifyCode('');
        } catch {
            addToast('Failed to connect to 2FA service.', 'error');
        } finally {
            setIsSettingUp(false);
        }
    }, [addToast]);

    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
    const [isRegenerating, setIsRegenerating] = useState(false);
    const [regenCode, setRegenCode] = useState('');
    const [showRegenConfirm, setShowRegenConfirm] = useState(false);

    const confirmSetup = useCallback(async () => {
        if (verifyCode.length < 6) {
            addToast('Please enter a 6-digit code from your authenticator app.', 'error');
            return;
        }
        setIsVerifying(true);
        try {
            const res = await apiFetch('/api/v1/auth/user/2fa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: verifyCode }),
            });
            const data = await res.json();
            if (!res.ok) {
                addToast(data.message || data.error || 'Verification failed.', 'error');
                return;
            }
            addToast('Two-factor authentication enabled successfully!', 'success');
            
            if (data.recovery_codes && data.recovery_codes.length > 0) {
                setRecoveryCodes(data.recovery_codes);
                setSetupData(null);
                setVerifyCode('');
            } else {
                setSetupData(null);
                setVerifyCode('');
                window.location.reload();
            }
        } catch {
            addToast('Failed to verify code.', 'error');
        } finally {
            setIsVerifying(false);
        }
    }, [verifyCode, addToast]);

    const regenerateRecoveryCodes = useCallback(async () => {
        if (regenCode.length !== 6) {
            addToast('Enter your current 6-digit TOTP code to regenerate backup codes.', 'error');
            return;
        }
        setIsRegenerating(true);
        try {
            const res = await apiFetch('/api/v1/auth/user/2fa/recovery/regenerate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: regenCode }),
            });
            const data = await res.json();
            if (!res.ok) {
                addToast(data.message || data.error || 'Regeneration failed.', 'error');
                return;
            }
            addToast('Recovery codes regenerated successfully!', 'success');
            setRecoveryCodes(data.recovery_codes);
            setShowRegenConfirm(false);
            setRegenCode('');
        } catch {
            addToast('Failed to regenerate codes.', 'error');
        } finally {
            setIsRegenerating(false);
        }
    }, [regenCode, addToast]);

    const disable2FA = useCallback(async () => {
        if (disableCode.length < 6) {
            addToast('Enter your current 6-digit code to disable 2FA.', 'error');
            return;
        }
        setIsDisabling(true);
        try {
            const res = await apiFetch('/api/v1/auth/user/2fa/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: disableCode }),
            });
            if (!res.ok) {
                const data = await res.json();
                addToast(data.message || data.error || 'Failed to disable 2FA.', 'error');
                return;
            }
            addToast('Two-factor authentication disabled.', 'info');
            setShowDisableConfirm(false);
            setDisableCode('');
            window.location.reload();
        } catch {
            addToast('Failed to disable 2FA.', 'error');
        } finally {
            setIsDisabling(false);
        }
    }, [disableCode, addToast]);

    const copySecret = useCallback(() => {
        if (setupData?.secret) {
            navigator.clipboard.writeText(setupData.secret);
            setSecretCopied(true);
            setTimeout(() => setSecretCopied(false), 2000);
        }
    }, [setupData]);

    return (
        <div className="animate-fade-in relative z-10 w-full">
            <div className="absolute inset-0 bg-red-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>
                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <Shield size={24} className="text-indigo-400" />
                    Security & Access Control
                </h2>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 relative z-10">
                    {/* Active Sessions Panel */}
                    <div className="lg:col-span-2 bg-slate-900/60 border border-white/5 rounded-2xl p-6">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-white/5">
                            <div>
                                <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                                    <MonitorSmartphone size={18} className="text-indigo-400" />
                                    Active Sessions
                                </h3>
                                <p className="text-sm text-slate-400 mt-1">Review and manage devices currently connected to this Nexus.</p>
                            </div>
                            <button 
                                onClick={revokeAllOthers}
                                className="glass-button text-sm px-4 py-2 text-red-300 hover:text-red-200 border-red-500/30 hover:border-red-500/50 hover:bg-red-500/10 transition-colors whitespace-nowrap">
                                Revoke All Others
                            </button>
                        </div>

                        <div className="space-y-4">
                            {sessions.map(session => (
                                <div key={session.jti} className={`flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-4 rounded-xl border ${session.is_current ? 'bg-indigo-500/10 border-indigo-500/30' : 'bg-white/[0.02] border-white/5'}`}>
                                    <div className="flex gap-4">
                                        <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${session.is_current ? 'bg-indigo-500/20 text-indigo-400' : 'bg-slate-800 text-slate-400'}`}>
                                            <Laptop size={20} />
                                        </div>
                                        <div>
                                            <div className="flex items-center gap-2">
                                                <span className="font-semibold text-slate-200">
                                                    {session.user_agent.length > 30 ? session.user_agent.substring(0, 30) + '...' : session.user_agent || 'Unknown Device'}
                                                </span>
                                                {session.is_current && (
                                                    <span className="text-[10px] bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded uppercase tracking-wider font-bold">This Device</span>
                                                )}
                                            </div>
                                            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 mt-1">
                                                <span className="text-slate-500" title={session.user_agent}>{session.user_agent.length > 50 ? session.user_agent.substring(0, 50) + '...' : session.user_agent || 'Unknown Browser'}</span>
                                                <span className="text-slate-500">{session.ip_address}</span>
                                            </div>
                                            <div className="text-xs text-slate-500 mt-1">Active: {new Date(session.last_active).toLocaleString()}</div>
                                        </div>
                                    </div>
                                    
                                    {!session.is_current && (
                                        <button 
                                            onClick={() => revokeSession(session.jti)}
                                            className="text-slate-500 hover:text-red-400 transition-colors p-2 rounded-lg hover:bg-red-500/10 self-end md:self-auto shrink-0"
                                            title="Revoke Session"
                                        >
                                            <XCircle size={20} />
                                        </button>
                                    )}
                                </div>
                            ))}
                            {sessions.length === 0 && (
                                <p className="text-slate-500 text-sm italic text-center py-4">No active sessions mapped.</p>
                            )}
                        </div>
                    </div>

                    {/* Two-Factor Authentication Panel */}
                    <div className="bg-slate-900/60 border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <Lock className="text-slate-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">Two-Factor Authentication</h3>
                        </div>

                        {/* Recovery Codes Modal-like Overlay */}
                        {recoveryCodes.length > 0 && (
                            <div className="mb-6 p-6 bg-indigo-500/10 border border-indigo-500/20 rounded-2xl animate-in zoom-in-95 duration-300">
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-2">
                                        <ShieldCheck className="text-emerald-400" size={20} />
                                        <h4 className="font-bold text-slate-100">Your Recovery Codes</h4>
                                    </div>
                                    <button 
                                        onClick={() => window.location.reload()}
                                        className="text-[10px] uppercase tracking-widest font-bold text-slate-500 hover:text-white transition-colors"
                                    >
                                        Close & Finish
                                    </button>
                                </div>
                                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                                    Save these codes in a secure place. They will not be shown again. 
                                    Each code can only be used once to unlock your account if you lose your device.
                                </p>
                                <div className="grid grid-cols-2 gap-2 mb-6">
                                    {recoveryCodes.map((code, i) => (
                                        <div key={i} className="bg-slate-950/80 border border-white/10 rounded-lg py-2 px-3 text-center font-mono text-sm tracking-widest text-indigo-300">
                                            {code}
                                        </div>
                                    ))}
                                </div>
                                <div className="flex flex-col gap-3">
                                    <button 
                                        onClick={() => {
                                            navigator.clipboard.writeText(recoveryCodes.join('\n'));
                                            addToast('All recovery codes copied to clipboard.', 'success');
                                        }}
                                        className="w-full py-2.5 bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-500/30 rounded-xl text-xs font-bold text-indigo-200 transition-colors flex items-center justify-center gap-2"
                                    >
                                        <Copy size={14} /> Copy All Codes
                                    </button>
                                    <button 
                                        onClick={() => window.location.reload()}
                                        className="w-full py-3 bg-white/5 border border-white/10 hover:bg-emerald-500/20 hover:border-emerald-500/40 rounded-xl text-xs font-bold text-slate-300 hover:text-emerald-300 transition-all uppercase tracking-widest"
                                    >
                                        I have saved my codes
                                    </button>
                                </div>
                            </div>
                        )}

                        {is2FAEnabled ? (
                            /* ── 2FA is ENABLED ── */
                            <div className="space-y-4">
                                <div className="flex items-center gap-3 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                                    <ShieldCheck size={24} className="text-emerald-400 shrink-0" />
                                    <div>
                                        <p className="text-sm font-bold text-emerald-300">Two-Factor Authentication is Active</p>
                                        <p className="text-xs text-slate-400 mt-1">Your account is protected with TOTP-based verification.</p>
                                    </div>
                                </div>

                                {/* Recovery Codes Regeneration Section */}
                                <div className="mt-6 pt-6 border-t border-white/5 space-y-4">
                                    <div className="flex items-center justify-between">
                                        <h4 className="text-sm font-bold text-slate-300">Backup Recovery Codes</h4>
                                        {!showRegenConfirm && (
                                            <button 
                                                onClick={() => setShowRegenConfirm(true)}
                                                className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 transition-colors"
                                            >
                                                Regenerate
                                            </button>
                                        )}
                                    </div>
                                    
                                    {showRegenConfirm ? (
                                        <div className="space-y-3 p-4 bg-indigo-500/5 border border-indigo-500/20 rounded-xl">
                                            <p className="text-xs text-indigo-300 font-semibold">Enter TOTP code to generate new backup codes:</p>
                                            <input
                                                type="text"
                                                inputMode="numeric"
                                                maxLength={6}
                                                value={regenCode}
                                                onChange={e => setRegenCode(e.target.value.replace(/\D/g, ''))}
                                                placeholder="000000"
                                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-2 text-slate-200 text-center text-xl tracking-[0.3em] font-mono focus:outline-none focus:border-indigo-500/50 transition-colors"
                                                autoFocus
                                            />
                                            <div className="flex gap-2">
                                                <button
                                                    onClick={regenerateRecoveryCodes}
                                                    disabled={isRegenerating || regenCode.length < 6}
                                                    className="flex-1 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/30 rounded-lg text-xs font-bold text-white transition-all flex items-center justify-center gap-2"
                                                >
                                                    {isRegenerating && <Loader2 size={12} className="animate-spin" />}
                                                    {isRegenerating ? 'Generating...' : 'Confirm'}
                                                </button>
                                                <button
                                                    onClick={() => { setShowRegenConfirm(false); setRegenCode(''); }}
                                                    className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-xs font-bold text-slate-300 transition-colors"
                                                >
                                                    Cancel
                                                </button>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className="text-xs text-slate-500 leading-relaxed">
                                            If you've used your recovery codes or believe they've been compromised, you can generate a new set. This will invalidate all previous codes.
                                        </p>
                                    )}
                                </div>

                                {showDisableConfirm ? (
                                    <div className="mt-8 pt-8 border-t border-white/5 space-y-4">
                                        <p className="text-sm text-red-300 font-semibold flex items-center gap-2">
                                            <ShieldOff size={16} /> Disable Two-Factor Authentication
                                        </p>
                                        <div className="space-y-4 p-4 bg-red-500/5 border border-red-500/20 rounded-xl">
                                            <p className="text-sm text-red-300 font-semibold">Enter your current authenticator code to confirm:</p>
                                            <input
                                                type="text"
                                                inputMode="numeric"
                                                maxLength={6}
                                                value={disableCode}
                                                onChange={e => setDisableCode(e.target.value.replace(/\D/g, ''))}
                                                placeholder="000000"
                                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-center text-2xl tracking-[0.5em] font-mono focus:outline-none focus:border-red-500/50 transition-colors"
                                                autoFocus
                                            />
                                            <div className="flex gap-3">
                                                <button
                                                    onClick={disable2FA}
                                                    disabled={isDisabling || disableCode.length < 6}
                                                    className="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-red-600/30 disabled:text-slate-500 rounded-xl text-sm font-bold text-white transition-all flex items-center justify-center gap-2"
                                                >
                                                    {isDisabling && <Loader2 size={16} className="animate-spin" />}
                                                    {isDisabling ? 'Disabling...' : 'Confirm Disable'}
                                                </button>
                                                <button
                                                    onClick={() => { setShowDisableConfirm(false); setDisableCode(''); }}
                                                    className="px-4 py-2.5 bg-white/5 border border-white/10 hover:bg-white/10 rounded-xl text-sm font-bold text-slate-300 transition-colors"
                                                >
                                                    Cancel
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <button
                                        onClick={() => setShowDisableConfirm(true)}
                                        className="w-full text-left px-4 py-3 border border-red-500/20 text-red-300 hover:bg-red-500/10 hover:border-red-500/30 rounded-xl flex items-center gap-2 cursor-pointer transition-colors mt-8"
                                    >
                                        <ShieldOff size={16} /> Disable Two-Factor Authentication
                                    </button>
                                )}
                            </div>
                        ) : setupData ? (
                            /* ── 2FA SETUP IN PROGRESS ── */
                            <div className="space-y-5">
                                <p className="text-sm text-slate-400">
                                    Scan the QR code below with your authenticator app (e.g. Google Authenticator, Authy, 1Password).
                                </p>

                                {/* QR Code */}
                                <div className="flex justify-center">
                                    <div className="bg-white p-4 rounded-2xl shadow-lg">
                                        <QRCodeSVG
                                            value={setupData.otpauth_uri}
                                            size={200}
                                            level="M"
                                            includeMargin={false}
                                        />
                                    </div>
                                </div>

                                {/* Manual Entry Secret */}
                                <div className="space-y-2">
                                    <p className="text-xs text-slate-500 uppercase tracking-wider font-bold">Manual Entry Key</p>
                                    <div className="flex items-center gap-2">
                                        <code className="flex-1 bg-slate-950 border border-white/10 rounded-xl px-4 py-3 text-indigo-300 text-sm font-mono tracking-wider break-all select-all">
                                            {setupData.secret}
                                        </code>
                                        <button
                                            onClick={copySecret}
                                            className="shrink-0 p-3 bg-white/5 border border-white/10 rounded-xl text-slate-400 hover:text-white transition-colors"
                                            title="Copy secret"
                                        >
                                            {secretCopied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
                                        </button>
                                    </div>
                                </div>

                                {/* Verification Input */}
                                <div className="space-y-3 pt-2 border-t border-white/5">
                                    <p className="text-sm text-slate-300 font-semibold">Enter the 6-digit code to verify:</p>
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        maxLength={6}
                                        value={verifyCode}
                                        onChange={e => setVerifyCode(e.target.value.replace(/\D/g, ''))}
                                        placeholder="000000"
                                        className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-center text-2xl tracking-[0.5em] font-mono focus:outline-none focus:border-indigo-500/50 transition-colors"
                                        onKeyDown={e => { if (e.key === 'Enter') confirmSetup(); }}
                                    />
                                    <div className="flex gap-3">
                                        <button
                                            onClick={confirmSetup}
                                            disabled={isVerifying || verifyCode.length < 6}
                                            className="flex-1 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/30 disabled:text-slate-500 rounded-xl text-sm font-bold text-white transition-all flex items-center justify-center gap-2"
                                        >
                                            {isVerifying && <Loader2 size={16} className="animate-spin" />}
                                            {isVerifying ? 'Verifying...' : 'Enable 2FA'}
                                        </button>
                                        <button
                                            onClick={() => { setSetupData(null); setVerifyCode(''); }}
                                            className="px-4 py-2.5 bg-white/5 border border-white/10 hover:bg-white/10 rounded-xl text-sm font-bold text-slate-300 transition-colors"
                                        >
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ) : (
                            /* ── 2FA NOT ENROLLED ── */
                            <div className="space-y-4">
                                <p className="text-sm text-slate-400 mb-6">Add an extra layer of security to your account with time-based one-time passwords (TOTP).</p>
                                <button
                                    onClick={initSetup}
                                    disabled={isSettingUp}
                                    className="glass-button-primary w-full px-4 py-3 text-center flex items-center justify-center gap-2"
                                >
                                    {isSettingUp ? (
                                        <><Loader2 size={16} className="animate-spin" /> Generating Key...</>
                                    ) : (
                                        <><ShieldCheck size={16} /> Enable Two-Factor Authentication</>
                                    )}
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Infrastructure API */}
                    <div className="bg-slate-900/60 border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <KeyRound className="text-slate-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">Infrastructure Keys</h3>
                        </div>
                        <p className="text-sm text-slate-400 mb-6">Tokens authorizing unattended script execution and remote daemon management.</p>

                        <button 
                            onClick={() => addToast('New service principle token generated.', 'success')}
                            className="glass-button-primary w-full px-4 py-3 mt-4 text-center">
                            Generate Service Token
                        </button>
                    </div>
                </div>
        </div>
    );
}
