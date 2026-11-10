'use client';

import { useAuth } from '@/contexts/AuthContext';
import { ShieldCheck, ShieldAlert, Check, X, Loader2, User, Mail, Database, Globe } from 'lucide-react';
import { motion } from 'framer-motion';
import { MotionPresets } from '@/lib/design';
import { useState, useEffect, type ComponentType } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { apiFetch } from '@/lib/fetcher';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';

function getConsentRequestError(clientId: string | null, redirectUri: string | null, responseType: string | null): string {
    if (!clientId?.trim() || !redirectUri?.trim() || !responseType?.trim()) {
        return 'This link is missing information required to identify the application and its authorization request.';
    }
    if (responseType !== 'code') {
        return 'This authorization request uses an unsupported response type. AetherFlow requires the authorization code flow.';
    }
    try {
        const target = new URL(redirectUri);
        const authority = redirectUri.match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i)?.[1];
        const specialScheme = ['http:', 'https:', 'ws:', 'wss:', 'ftp:'].includes(target.protocol);
        if (['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:'].includes(target.protocol)
            || /[\u0000-\u0020\u007f]/.test(redirectUri)
            || redirectUri.includes('#')
            || authority?.includes('@')
            || target.username || target.password
            || (specialScheme && (!authority || redirectUri.split('?')[0].includes('\\')))
            || (!target.hostname && !target.pathname)) {
            return 'This authorization request has an invalid callback URI. Use an absolute application callback URI without credentials or a fragment.';
        }
    } catch {
        return 'This authorization request has an invalid callback URI. Use an absolute application callback URI.';
    }
    return '';
}

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
    const nonce = searchParams.get('nonce');
    const codeChallenge = searchParams.get('code_challenge');
    const codeChallengeMethod = searchParams.get('code_challenge_method');
    const requestError = getConsentRequestError(clientId, redirectUri, responseType);

    const scopeList = scope.split(' ').map(s => s.trim()).filter(Boolean);

    useEffect(() => {
        if (!authLoading && !isAuthenticated) {
            const returnTo = encodeURIComponent(window.location.pathname + window.location.search);
            router.replace(`/login?return_to=${returnTo}`);
        }
    }, [isAuthenticated, authLoading, router]);

    const handleConsent = async (approved: boolean) => {
        if (requestError) {
            setError(requestError);
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
                    nonce: nonce || '',
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
                setError(data.message || data.error || 'Authorization sequence refused by operator core.');
                setIsSubmitting(false);
            }
        } catch (_err) {
            setError('Transaction failed. Cannot communicate with authorization provider.');
            setIsSubmitting(false);
        }
    };

    if (authLoading || !isAuthenticated) {
        return (
            <div className="min-h-screen bg-transparent flex items-center justify-center">
                <Loader2 size={32} className="animate-spin text-indigo-500" />
            </div>
        );
    }

    if (requestError) {
        return (
            <main aria-labelledby="invalid-authorization-heading" className="min-h-screen bg-transparent px-5 py-10 sm:px-8 sm:py-16">
                <div className="mx-auto w-full max-w-3xl">
                    <header className="pb-6">
                        <div className="obs-brand-logo h-16 w-16 mb-5 flex items-center justify-center">
                            <ShieldAlert size={36} className="obs-brand-mark text-amber-400" aria-hidden="true" />
                        </div>
                        <p className="mb-2 text-xs font-medium uppercase tracking-wider text-indigo-300">AetherFlow · Authorization</p>
                        <h1 id="invalid-authorization-heading" className="text-2xl font-bold text-white mb-3">Invalid Authorization Request</h1>
                        <p className="max-w-xl text-sm leading-relaxed text-slate-300">{requestError} No access has been granted.</p>
                    </header>
                    <section aria-labelledby="authorization-recovery-heading" className="border-t border-white/[0.07] py-6">
                        <h2 id="authorization-recovery-heading" className="mb-3 text-base font-semibold text-slate-100">Start again safely</h2>
                        <ol className="mb-6 list-decimal space-y-2 pl-5 text-sm leading-relaxed text-slate-300">
                            <li>Return to the application that sent you here and start its sign-in flow again.</li>
                            <li>If the new link still fails, ask the application owner to check its authorization configuration.</li>
                        </ol>
                        <Link href="/" className="obs-touch-target-standard inline-flex min-h-[44px] items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] px-4 py-2.5 text-sm font-medium text-indigo-200 hover:bg-white/[0.08] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400">Open AetherFlow</Link>
                    </section>
                </div>
            </main>
        );
    }

    return (
        <div className="min-h-screen bg-transparent flex flex-col justify-center relative selection:bg-indigo-500/30">
            <motion.div
                className="w-full relative z-10"
                variants={MotionPresets.slideUp}
                initial="hidden"
                animate="visible"
            >
                <div>
                    <header className="w-full border-b border-white/[0.07] p-6 sm:p-8 text-center">
                        <div className="w-full max-w-md mx-auto">
                            <div className="obs-brand-logo mx-auto h-16 w-16 mb-4 flex items-center justify-center">
                                <ShieldCheck size={36} className="obs-brand-mark text-indigo-300" />
                            </div>
                            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
                                Operator Action Required
                            </h1>
                            <p className="text-slate-400 text-sm mt-2 font-medium">
                                <span className="text-indigo-300 font-bold">{clientId}</span> is requesting explicit authorization to access your identity context.
                            </p>
                        </div>
                    </header>

                    <div className="w-full border-b border-white/[0.07] p-6 sm:p-8">
                        <div className="w-full max-w-md mx-auto">
                            <div className="mb-6 space-y-2 pb-6 border-b border-white/[0.07]">
                                <label htmlFor="oauth-redirect-uri" className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 block">
                                    Target Redirect URI
                                </label>
                                <Input
                                    id="oauth-redirect-uri"
                                    type="text"
                                    readOnly
                                    value={redirectUri || ''}
                                    className="text-xs font-mono bg-black/40 text-slate-300 border-white/10 select-all cursor-default w-full break-all"
                                />
                            </div>

                            <div className="mb-6 space-y-3">
                                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 text-center">
                                    Requested Scopes
                                </h3>
                                <ul className="divide-y divide-white/[0.07] border-y border-white/[0.07]">
                                    {scopeList.map(scopeItem => {
                                        const SCOPE_METADATA: Record<string, { desc: string, icon: ComponentType<{ size?: number; className?: string }>, alertLevel?: 'danger' | 'warning' | 'info' }> = {
                                            openid: { desc: 'Core federated identity context', icon: Globe, alertLevel: 'info' },
                                            profile: { desc: 'Basic identity attributes', icon: User, alertLevel: 'info' },
                                            email: { desc: 'Primary contact address visibility', icon: Mail, alertLevel: 'info' },
                                            'system:read': { desc: 'Read-only telemetry and health metrics access', icon: Database, alertLevel: 'info' },
                                            'system:write': { desc: 'Mutate core daemon configurations and processes', icon: ShieldAlert, alertLevel: 'danger' },
                                            'system:auth': { desc: 'Manage downstream service principle tokens', icon: ShieldAlert, alertLevel: 'danger' },
                                            'fileshare:read': { desc: 'Read-only access to storage pool artifacts', icon: Database, alertLevel: 'info' },
                                            'fileshare:write': { desc: 'Upload or delete artifacts in the shared volume', icon: ShieldAlert, alertLevel: 'warning' }
                                        };

                                        const meta = SCOPE_METADATA[scopeItem] || { desc: `Unknown arbitrary scope requested: ${scopeItem}`, icon: ShieldAlert, alertLevel: 'warning' };
                                        const ScopeIcon = meta.icon;

                                        return (
                                            <li key={scopeItem} className={`flex items-start gap-3 py-3 px-2 transition-colors ${meta.alertLevel === 'danger' ? 'bg-red-500/[0.06]' : meta.alertLevel === 'warning' ? 'bg-amber-500/[0.06]' : 'bg-transparent hover:bg-white/[0.02]'}`}>
                                                <div className={`mt-0.5 p-2 rounded-md shrink-0 ${meta.alertLevel === 'danger' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : meta.alertLevel === 'warning' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/20'}`}>
                                                    <ScopeIcon size={18} />
                                                </div>
                                                <div className="min-w-0 flex-1">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className="text-sm font-bold text-slate-200 tracking-wide break-all">{scopeItem}</span>
                                                        {meta.alertLevel === 'danger' && (
                                                            <span className="text-xs uppercase tracking-widest bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded border border-red-500/30 font-bold shrink-0">Critical Impact</span>
                                                        )}
                                                    </div>
                                                    <span className={`text-xs block mt-1 font-medium leading-relaxed break-words ${meta.alertLevel === 'danger' ? 'text-red-300' : meta.alertLevel === 'warning' ? 'text-amber-300' : 'text-slate-400'}`}>{meta.desc}</span>
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
                        </div>
                    </div>

                    <footer className="w-full p-6 sm:p-8">
                        <div className="w-full max-w-md mx-auto space-y-3">
                            <Button
                                variant="primary"
                                onClick={() => handleConsent(true)}
                                disabled={isSubmitting}
                                className="w-full py-3.5 flex items-center justify-center gap-2 font-bold tracking-wide disabled:opacity-50"
                            >
                                {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : <Check size={18} />}
                                Grant Authorization
                            </Button>

                            <Button
                                variant="default"
                                onClick={() => handleConsent(false)}
                                disabled={isSubmitting}
                                className="w-full py-3.5 flex items-center justify-center gap-2 font-bold text-slate-300 tracking-wide disabled:opacity-50"
                            >
                                <X size={18} />
                                Reject & Revoke
                            </Button>
                        </div>
                    </footer>
                </div>

                <p className="text-center text-xs text-slate-400 mt-6 pb-6 px-4 uppercase tracking-wider font-semibold">
                    Trust before automation. Verify the client ID.
                </p>
            </motion.div>
        </div>
    );
}
