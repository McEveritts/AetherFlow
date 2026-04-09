'use client';

import { useAuth } from '@/contexts/AuthContext';
import { ShieldCheck, ShieldAlert, Check, X, Loader2 } from 'lucide-react';
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
                setError(data.error || 'Consent submission failed');
                setIsSubmitting(false);
            }
        } catch (_err) {
            setError('Network error submitting consent.');
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
                <div className="bg-slate-900 border border-red-500/20 p-8 rounded-3xl max-w-md w-full text-center">
                    <ShieldAlert size={48} className="text-red-400 mx-auto mb-4" />
                    <h2 className="text-xl font-bold text-white mb-2">Invalid Request</h2>
                    <p className="text-sm text-slate-400">The OAuth consent request is missing required parameters like client_id or redirect_uri.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center relative overflow-hidden selection:bg-indigo-500/30 p-6">
            <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
                <div className="absolute top-1/4 left-1/4 w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px]"></div>
            </div>

            <div className="w-full max-w-md relative z-10">
                <div className="bg-slate-950/80 backdrop-blur-2xl border border-white/10 rounded-3xl shadow-2xl overflow-hidden">
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>
                    
                    <div className="p-8 pb-6 text-center border-b border-white/5">
                        <div className="mx-auto h-16 w-16 mb-4 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-lg shadow-indigo-500/20 relative">
                            <ShieldCheck size={32} className="text-white" />
                        </div>
                        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
                            Authorization Request
                        </h1>
                        <p className="text-slate-400 text-sm mt-2">
                            {clientId ? `Application ${clientId} is requesting access to your AetherFlow account.` : 'An application is requesting access to your AetherFlow account.'}
                        </p>
                    </div>

                    <div className="p-8">
                        <div className="mb-6 bg-slate-900/50 border border-white/5 rounded-xl p-4">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
                                Requested Access
                            </h3>
                            <ul className="space-y-3">
                                {scopeList.map(s => (
                                    <li key={s} className="flex items-start gap-3">
                                        <div className="mt-0.5 bg-indigo-500/20 rounded-full p-1 border border-indigo-500/30">
                                            <Check size={12} className="text-indigo-400" />
                                        </div>
                                        <div>
                                            <span className="text-sm font-semibold text-slate-200 block capitalize">{s}</span>
                                            <span className="text-[10px] text-slate-500 block">Read your {s} information</span>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        </div>

                        {error && (
                            <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm text-center">
                                {error}
                            </div>
                        )}

                        <div className="space-y-3">
                            <button
                                onClick={() => handleConsent(true)}
                                disabled={isSubmitting}
                                className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-bold tracking-wide transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                            >
                                {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : <Check size={16} />}
                                Allow Access
                            </button>
                            
                            <button
                                onClick={() => handleConsent(false)}
                                disabled={isSubmitting}
                                className="w-full py-3 bg-transparent border border-white/10 hover:bg-white/5 text-slate-300 rounded-xl text-sm font-bold tracking-wide transition-all disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                            >
                                <X size={16} />
                                Deny
                            </button>
                        </div>
                    </div>
                </div>
                
                <p className="text-center text-[10px] text-slate-500 mt-6 px-4">
                    Only approve access for applications you trust. AetherFlow will never share your password.
                </p>
            </div>
        </div>
    );
}
