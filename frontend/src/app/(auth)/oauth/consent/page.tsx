'use client';

import { useAuth } from '@/contexts/AuthContext';
import { ShieldCheck, ShieldAlert, Check, X, Loader2, User, Mail, Database, Globe } from 'lucide-react';
import { motion } from 'framer-motion';
import { MotionPresets } from '@/lib/design';
import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { apiFetch } from '@/lib/fetcher';

export default function ConsentPage() {
    const { isAuthenticated, isLoading: authLoading } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');

    const clientId = searchParams.get('client_id');
    const redirectUri = searchParams.get('redirect_uri');
    const responseType = searchParams.get('response_type');
    const scope = searchParams.get('scope') || 'openid profile email';
    const state = searchParams.get('state');
    const codeChallenge = searchParams.get('code_challenge');
    const codeChallengeMethod = searchParams.get('code_challenge_method');

    const scopeList = scope.split(' ').map(s => s.trim()).filter(Boolean);

    useEffect(() => {
        if (!authLoading && !isAuthenticated) {
            const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
            router.replace(`/login?return_to=${returnTo}`);
        }
    }, [isAuthenticated, authLoading, router]);

    const handleConsent = async (approved: boolean) => {
        if (!clientId || !redirectUri || !responseType) {
            setError('Missing required OAuth parameters.');
            return;
        }

        setIsSubmitting(true);
        setError('');

        try {
            const res = await apiFetch('/api/v1/auth/oidc/consent', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    response_type: responseType,
                    scope,
                    state: state || '',
                    code_challenge: codeChallenge || '',
                    code_challenge_method: codeChallengeMethod || '',
                    approved,
                })
            });

            const data = await res.json();
            const redirectTarget = data.redirect_uri || data.redirect_url;
            if (res.ok && redirectTarget) {
                window.location.assign(redirectTarget);
            } else {
                setError(data.error || 'Authorization sequence refused by operator core.');
                setIsSubmitting(false);
            }
        } catch (_err) {
            setError('Transaction failed. Cannot communicate with authorization provider.');
            setIsSubmitting(false);
        }
    };

    if (authLoading || !isAuthenticated) {
        return (
            <div className="min-h-screen bg-slate-950 flex items-center justify-center">
                <Loader2 size={32} className="animate-spin text-indigo-500" />
            </div>
        );
    }

    if (!clientId || !redirectUri) {
        return (
            <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
                <div className="glass-panel border-red-500/20 p-8 rounded-3xl max-w-md w-full text-center">
                    <ShieldAlert size={48} className="text-red-400 mx-auto mb-4" />
                    <h2 className="text-xl font-bold text-white mb-2">Invalid Authorization Request</h2>
                    <p className="text-sm text-slate-400">The OIDC payload is malformed or missing critical validation parameters.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center relative overflow-hidden selection:bg-indigo-500/30 p-6">
            <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
                <div className="absolute top-1/4 left-1/4 w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px] mix-blend-screen"></div>
            </div>

            <motion.div 
                className="w-full max-w-md relative z-10"
                variants={MotionPresets.slideUp}
                initial="hidden"
                animate="visible"
            >
                <div className="glass-panel overflow-hidden rounded-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)]">
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>
                    
                    <div className="p-8 pb-6 text-center border-b border-white/5">
                        <div className="mx-auto h-16 w-16 mb-4 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-lg shadow-indigo-500/20 relative">
                            <ShieldCheck size={32} className="text-white" />
                        </div>
                        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
                            Operator Action Required
                        </h1>
                        <p className="text-slate-400 text-sm mt-2 font-medium">
                            <span className="text-indigo-300 font-bold">{clientId}</span> is requesting explicit authorization to access your identity context.
                        </p>
                    </div>

                    <div className="p-8">
                        <div className="mb-6 bg-slate-900/40 border border-white/5 rounded-xl p-4">
                            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 text-center">
                                Requested Scopes
                            </h3>
                            <ul className="space-y-3">
                                {scopeList.map(s => {
                                    const SCOPE_METADATA: Record<string, { desc: string, icon: any, alertLevel?: 'danger' | 'warning' | 'info' }> = {
                                        openid: { desc: 'Core federated identity context', icon: Globe, alertLevel: 'info' },
                                        profile: { desc: 'Basic identity attributes', icon: User, alertLevel: 'info' },
                                        email: { desc: 'Primary contact address visibility', icon: Mail, alertLevel: 'info' },
                                        'system:read': { desc: 'Read-only telemetry and health metrics access', icon: Database, alertLevel: 'info' },
                                        'system:write': { desc: 'Mutate core daemon configurations and processes', icon: ShieldAlert, alertLevel: 'danger' },
                                        'system:auth': { desc: 'Manage downstream service principle tokens', icon: ShieldAlert, alertLevel: 'danger' },
                                        'fileshare:read': { desc: 'Read-only access to storage pool artifacts', icon: Database, alertLevel: 'info' },
                                        'fileshare:write': { desc: 'Upload or delete artifacts in the shared volume', icon: ShieldAlert, alertLevel: 'warning' }
                                    };

                                    const meta = SCOPE_METADATA[s] || { desc: `Unknown arbitrary scope requested: ${s}`, icon: ShieldAlert, alertLevel: 'warning' };
                                    const ScopeIcon = meta.icon;

                                    return (
                                        <li key={s} className={`flex items-start gap-4 p-3 rounded-xl border ${meta.alertLevel === 'danger' ? 'bg-red-500/10 border-red-500/30' : meta.alertLevel === 'warning' ? 'bg-amber-500/10 border-amber-500/30' : 'bg-white/5 border-white/10 hover:bg-white/10'}`}>
                                            <div className={`mt-0.5 rounded-xl p-2.5 shadow-inner ${meta.alertLevel === 'danger' ? 'bg-red-500/20 text-red-400' : meta.alertLevel === 'warning' ? 'bg-amber-500/20 text-amber-400' : 'bg-indigo-500/20 text-indigo-400'}`}>
                                                <ScopeIcon size={18} />
                                            </div>
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-sm font-bold text-slate-200 tracking-wide">{s}</span>
                                                    {meta.alertLevel === 'danger' && (
                                                        <span className="text-[9px] uppercase tracking-widest bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded border border-red-500/30 font-bold">Critical Impact</span>
                                                    )}
                                                </div>
                                                <span className={`text-xs block mt-1 font-medium ${meta.alertLevel === 'danger' ? 'text-red-300' : meta.alertLevel === 'warning' ? 'text-amber-300' : 'text-slate-400'}`}>{meta.desc}</span>
                                            </div>
                                        </li>
                                    );
                                })}
                            </ul>
                        </div>

                        {error && (
                            <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center justify-center text-red-400 text-sm text-center font-medium">
                                {error}
                            </div>
                        )}

                        <div className="space-y-3">
                            <button
                                onClick={() => handleConsent(true)}
                                disabled={isSubmitting}
                                className="glass-button-primary w-full py-3.5 flex items-center justify-center gap-2 font-bold tracking-wide disabled:opacity-50"
                            >
                                {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : <Check size={18} />}
                                Grant Authorization
                            </button>
                            
                            <button
                                onClick={() => handleConsent(false)}
                                disabled={isSubmitting}
                                className="glass-button w-full py-3.5 flex items-center justify-center gap-2 font-bold text-slate-300 tracking-wide disabled:opacity-50"
                            >
                                <X size={18} />
                                Reject & Revoke
                            </button>
                        </div>
                    </div>
                </div>
                
                <p className="text-center text-[10px] text-slate-500 mt-6 px-4 uppercase tracking-wider font-semibold">
                    Trust before automation. Verify the client ID.
                </p>
            </motion.div>
        </div>
    );
}
