'use client';

import { useAuth } from '@/contexts/AuthContext';
import { Sparkles, KeyRound, LogIn, ShieldCheck, ArrowRight, Fingerprint, Info } from 'lucide-react';
import { FormEvent, useState, useEffect, useRef, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { apiFetch } from '@/lib/fetcher';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';

type AuthStep = 'credentials' | 'mfa_challenge' | 'mfa_setup';

function LoginFormContent() {
    const { login, loginLocal } = useAuth();
    const searchParams = useSearchParams();
    const [step, setStep] = useState<AuthStep>('credentials');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState(['', '', '', '', '', '']);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [isSetup, setIsSetup] = useState(false);
    
    const [mfaToken, setMfaToken] = useState('');
    const [isRecoveryMode, setIsRecoveryMode] = useState(false);
    const [recoveryCode, setRecoveryCode] = useState('');
    
    const mfaRefs = [
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
    ];

    const mfaHandledRef = useRef(false);
    const errorHandledRef = useRef(false);

    useEffect(() => {
        apiFetch('/api/v1/public/auth/setup/check')
            .then(res => res.json())
            .then(data => setIsSetup(data.setupRequired))
            .catch(() => { });

        // OPUS-002: Sol redirects Google users needing MFA to /login?mfa=<challenge>
        // Or if Google account is not allowlisted: /login?error=not_authorized
        const urlParams = typeof window !== 'undefined'
            ? new URLSearchParams(window.location.search)
            : null;
        const mfaChallenge = searchParams?.get('mfa') || urlParams?.get('mfa');
        const errorParam = searchParams?.get('error') || urlParams?.get('error');

        if (mfaChallenge && !mfaHandledRef.current) {
            mfaHandledRef.current = true;
            setMfaToken(mfaChallenge);
            setStep('mfa_challenge');

            // Clear sensitive challenge token from browser address bar & history immediately
            if (typeof window !== 'undefined') {
                const url = new URL(window.location.href);
                url.searchParams.delete('mfa');
                const remaining = url.searchParams.toString();
                window.history.replaceState(null, '', url.pathname + (remaining ? `?${remaining}` : ''));
            }
        }

        if (errorParam && !errorHandledRef.current) {
            errorHandledRef.current = true;
            if (errorParam === 'not_authorized') {
                setError('Google account is not authorized. Access is restricted to invited or allowlisted users.');
            } else {
                setError(`Authentication failed: ${errorParam.replace(/_/g, ' ')}`);
            }

            if (typeof window !== 'undefined') {
                const url = new URL(window.location.href);
                url.searchParams.delete('error');
                const remaining = url.searchParams.toString();
                window.history.replaceState(null, '', url.pathname + (remaining ? `?${remaining}` : ''));
            }
        }
    }, [searchParams]);

    const handleLogin = async (e: FormEvent) => {
        e.preventDefault();
        if (!username.trim() || !password.trim()) return;

        setIsLoading(true);
        setError('');

        try {
            const endpoint = isSetup ? '/api/v1/public/auth/setup' : '/api/v1/public/auth/login';
            const res = await apiFetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username.trim(), password: password.trim() })
            });

            const data = await res.json();

            if (res.ok) {
                if (data.requires_mfa) {
                    setMfaToken(data.mfa_token);
                    setStep('mfa_challenge');
                } else if (data.requires_mfa_setup) {
                    setStep('mfa_setup');
                } else {
                    loginLocal();
                }
            } else {
                const errMsg = data.message || data.error;
                setError(
                    errMsg?.includes('credentials') ? 'Authentication denied: Invalid credentials provided.' :
                    errMsg?.includes('locked') ? 'Identity locked: Maximum attempts exceeded. Try again in 15m.' :
                    errMsg || 'Authentication sequence failed. Check daemon logs.'
                );
            }
        } catch (_err) {
            setError('Connection to identity provider lost. Is the backend service active?');
        } finally {
            setIsLoading(false);
        }
    };

    const handleMfaSubmit = async (e: FormEvent) => {
        e.preventDefault();
        const code = isRecoveryMode ? recoveryCode : mfaCode.join('');
        if (!isRecoveryMode && code.length !== 6) return;
        if (isRecoveryMode && !code.trim()) return;

        setIsLoading(true);
        setError('');

        try {
            const res = await apiFetch('/api/v1/public/auth/mfa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mfa_token: mfaToken, code: code.trim() })
            });

            const data = await res.json();

            if (res.ok) {
                loginLocal();
            } else {
                setError(data.message || data.error || 'Verification failed. Check your code and try again.');
            }
        } catch (_err) {
             setError('Cryptographic verification failed. Check clock sync or token validity.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleMfaChange = (index: number, value: string) => {
        if (!/^[0-9]*$/.test(value)) return;
        const newCode = [...mfaCode];
        newCode[index] = value;
        setMfaCode(newCode);

        // Auto advance
        if (value && index < 5) {
            mfaRefs[index + 1].current?.focus();
        }
    };

    const handleMfaKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Backspace' && !mfaCode[index] && index > 0) {
            mfaRefs[index - 1].current?.focus();
        }
        // Handle paste
        if (e.key === 'v' && e.metaKey) {
            // Allow native paste event to fire
        }
    };
    
    const handlePaste = (e: React.ClipboardEvent) => {
        e.preventDefault();
        const pastedData = e.clipboardData.getData('text').slice(0, 6).replace(/[^0-9]/g, '');
        if (pastedData) {
            const newCode = [...mfaCode];
            for (let i = 0; i < pastedData.length; i++) {
                if (i < 6) newCode[i] = pastedData[i];
            }
            setMfaCode(newCode);
            if (pastedData.length === 6) {
                mfaRefs[5].current?.focus();
            } else {
                mfaRefs[pastedData.length].current?.focus();
            }
        }
    };

    return (
        <div className="min-h-screen bg-transparent flex flex-col justify-center relative selection:bg-indigo-500/30">
            <header className="w-full border-b border-white/[0.07] px-4 py-8 sm:py-10 text-center">
                <div className="w-full max-w-md mx-auto">
                    {step === 'credentials' ? (
                        <div className="obs-brand-logo mx-auto h-20 w-20 mb-6 flex items-center justify-center">
                            <img src="/img/aetherflow-mark.svg" alt="AetherFlow Logo" className="obs-brand-mark w-16 h-16 object-contain" />
                        </div>
                    ) : (
                        <div className="obs-brand-logo mx-auto h-16 w-16 mb-6 flex items-center justify-center">
                            <Fingerprint className="obs-brand-mark text-indigo-300 w-10 h-10 drop-shadow-md" />
                        </div>
                    )}
                    <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                        {isSetup ? 'Initialize Nexus' : (step === 'credentials' ? 'AetherFlow' : 'Verify Identity')}
                    </h1>
                    <p className="text-slate-400 text-sm mt-2 font-medium">
                        {isSetup ? 'Create primary administrative context' : (step === 'credentials' ? 'Welcome to the Aether' : 'Multi-factor authentication required')}
                    </p>
                </div>
            </header>

            <main className="w-full border-b border-white/[0.07] px-4 py-8 sm:py-10">
                <div className="w-full max-w-md mx-auto">
                    {error && (
                        <div className="mb-6 p-3 bg-red-500/10 border border-red-500/30 rounded-xl flex gap-3 text-red-200 text-sm">
                            <Info size={18} className="text-red-400 mt-0.5 shrink-0" />
                            <p className="leading-snug">{error}</p>
                        </div>
                    )}

                    {step === 'credentials' && (
                        <form onSubmit={handleLogin} className="space-y-6">
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="login-username" className="block text-sm font-medium text-slate-300 mb-2">{isSetup ? 'Administrative username' : 'Username'}</label>
                                    <div className="relative">
                                    <Input
                                        id="login-username"
                                        autoComplete="username"
                                        type="text"
                                        placeholder={isSetup ? 'Choose administrative operator ID' : 'Username'}
                                        value={username}
                                        onChange={(event) => setUsername(event.target.value)}
                                        required
                                        autoFocus
                                        className="pl-11 !text-sm font-medium"
                                    />
                                    <ShieldCheck size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                    </div>
                                </div>
                                <div>
                                    <label htmlFor="login-password" className="block text-sm font-medium text-slate-300 mb-2">Password</label>
                                    <div className="relative">
                                    <Input
                                        id="login-password"
                                        autoComplete={isSetup ? 'new-password' : 'current-password'}
                                        type="password"
                                        placeholder={isSetup ? 'Establish cryptographic key (min 6)' : 'Password'}
                                        value={password}
                                        onChange={(event) => setPassword(event.target.value)}
                                        required
                                        minLength={isSetup ? 6 : 1}
                                        className="pl-11 !text-sm font-medium"
                                    />
                                    <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                    </div>
                                </div>
                            </div>

                            <Button
                                type="submit"
                                variant="primary"
                                disabled={isLoading}
                                className="w-full py-3.5 flex items-center justify-center gap-2 font-semibold tracking-wide disabled:opacity-50"
                            >
                                <LogIn size={18} className={isLoading ? "animate-pulse" : ""} />
                                {isLoading ? 'Authenticating...' : (isSetup ? 'Initialize Identity' : 'Unlock the Aether')}
                            </Button>
                        </form>
                    )}

                    {step === 'mfa_challenge' && (
                        <form onSubmit={handleMfaSubmit} className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
                            {isRecoveryMode ? (
                                <div className="space-y-4">
                                    <div className="relative">
                                        <Input
                                            type="text"
                                            placeholder="XXXX-XXXX"
                                            value={recoveryCode}
                                            onChange={(event) => setRecoveryCode(event.target.value.toUpperCase())}
                                            required
                                            autoFocus
                                            className="pl-11 !text-sm font-bold tracking-widest font-mono"
                                        />
                                        <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                    </div>
                                    <p className="text-xs text-slate-400 leading-relaxed text-center px-4">
                                        Enter one of your 8-character recovery codes to unlock your account.
                                    </p>
                                </div>
                            ) : (
                                <div className="flex justify-between gap-2 px-1">
                                    {mfaCode.map((digitValue, digitIndex) => (
                                        <input
                                            key={digitIndex}
                                            ref={mfaRefs[digitIndex]}
                                            type="text"
                                            maxLength={1}
                                            value={digitValue}
                                            onChange={(event) => handleMfaChange(digitIndex, event.target.value)}
                                            onKeyDown={(event) => handleMfaKeyDown(digitIndex, event)}
                                            onPaste={handlePaste}
                                            className="glass-input w-12 h-14 text-center text-xl font-bold font-mono !px-0 focus:ring-2 focus:ring-indigo-500"
                                        />
                                    ))}
                                </div>
                            )}

                            <div className="space-y-4">
                                <Button
                                    type="submit"
                                    variant="primary"
                                    disabled={isLoading || (!isRecoveryMode && mfaCode.join('').length !== 6) || (isRecoveryMode && !recoveryCode.trim())}
                                    className="w-full py-3.5 flex items-center justify-center gap-2 font-semibold tracking-wide disabled:opacity-50"
                                >
                                    {isLoading ? 'Verifying Context...' : 'Authorize Action'}
                                    {!isLoading && <ArrowRight size={18} />}
                                </Button>
                                
                                <div className="flex flex-col gap-3">
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        onClick={() => setIsRecoveryMode(!isRecoveryMode)}
                                        className="w-full text-center text-indigo-400 hover:text-indigo-300 text-sm font-medium transition-colors"
                                    >
                                        {isRecoveryMode ? 'Use authentication app' : 'Lost your device? Use recovery code'}
                                    </Button>
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        onClick={() => {
                                            setStep('credentials');
                                            setIsRecoveryMode(false);
                                            setMfaToken('');
                                            setMfaCode(['', '', '', '', '', '']);
                                            setRecoveryCode('');
                                            setError('');
                                        }}
                                        className="w-full text-center text-slate-400 hover:text-slate-200 text-sm font-medium transition-colors"
                                    >
                                        Cancel and return
                                    </Button>
                                </div>
                            </div>
                        </form>
                    )}
                </div>
            </main>

            {step === 'credentials' && (
                <footer className="w-full px-4 py-8 text-center relative">
                    <div className="w-full max-w-md mx-auto">
                        <div className="text-xs font-semibold text-slate-400 tracking-widest uppercase mb-3">
                            External Providers
                        </div>
                        <Button
                            type="button"
                            variant="default"
                            onClick={() => login()}
                            className="w-full py-3 text-sm font-semibold flex items-center justify-center gap-2 text-slate-200"
                        >
                            <Sparkles size={16} className="text-indigo-400" />
                            Authenticate via OIDC Core
                        </Button>
                    </div>
                </footer>
            )}
        </div>
    );
}

export default function LoginPage() {
    return (
        <Suspense fallback={
            <div className="min-h-screen bg-transparent flex flex-col justify-center">
                <div className="w-full border-b border-white/[0.07] px-4 py-8 sm:py-10 text-center text-slate-400">
                    <div className="w-full max-w-md mx-auto">
                        <div className="obs-brand-logo mx-auto h-20 w-20 mb-6 flex items-center justify-center">
                            <img src="/img/aetherflow-mark.svg" alt="AetherFlow Logo" className="obs-brand-mark w-16 h-16 object-contain" />
                        </div>
                        <p className="text-sm font-medium">Verifying session context...</p>
                    </div>
                </div>
            </div>
        }>
            <LoginFormContent />
        </Suspense>
    );
}
