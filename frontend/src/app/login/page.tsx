'use client';

import { useAuth } from '@/contexts/AuthContext';
import { Sparkles, KeyRound, LogIn, ShieldCheck, ArrowRight, Fingerprint, Info } from 'lucide-react';
import { FormEvent, useState, useEffect, useRef } from 'react';
import { apiFetch } from '@/lib/fetcher';

type AuthStep = 'credentials' | 'mfa_challenge' | 'mfa_setup';

export default function LoginPage() {
    const { login, loginLocal } = useAuth();
    const [step, setStep] = useState<AuthStep>('credentials');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [mfaCode, setMfaCode] = useState(['', '', '', '', '', '']);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [isSetup, setIsSetup] = useState(false);
    
    const mfaRefs = [
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
        useRef<HTMLInputElement>(null),
    ];

    useEffect(() => {
        apiFetch('/api/v1/public/auth/setup/check')
            .then(res => res.json())
            .then(data => setIsSetup(data.setupRequired))
            .catch(() => { });
    }, []);

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
                // If API supports MFA in the future, it might return requires_mfa
                if (data.requires_mfa) {
                    setStep('mfa_challenge');
                } else if (data.requires_mfa_setup) {
                    setStep('mfa_setup');
                } else {
                    loginLocal();
                }
            } else {
                // Phase 26: Error-state language system
                // Replace generic errors with operator-facing language
                setError(
                    data.error?.includes('credentials') ? 'Authentication denied: Invalid credentials provided.' :
                    data.error?.includes('locked') ? 'Identity locked: Maximum attempts exceeded. Try again in 15m.' :
                    data.error || 'Authentication sequence failed. Check daemon logs.'
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
        const code = mfaCode.join('');
        if (code.length !== 6) return;

        setIsLoading(true);
        setError('');

        // Mocking the MFA verification step for the UX flow
        try {
            // Future implementation: POST /api/v1/public/auth/mfa/verify
            setTimeout(() => {
                loginLocal();
            }, 800);
        } catch (_err) {
             setError('Cryptographic verification failed. Check clock sync or token validity.');
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
        <div className="min-h-screen bg-slate-950 flex items-center justify-center relative overflow-hidden selection:bg-indigo-500/30">
            {/* Background ambient lighting */}
            <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
                <div className="absolute top-1/4 left-1/4 w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px] mix-blend-screen"></div>
                <div className="absolute bottom-1/4 right-1/4 w-[40%] h-[40%] bg-blue-900/10 rounded-full blur-[100px] mix-blend-screen"></div>
            </div>

            <div className="w-full max-w-md p-8 relative z-10 transition-all duration-500">
                <div className="glass-panel overflow-hidden rounded-3xl p-8 relative shadow-2xl">
                    {/* Header Glow */}
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/80 to-transparent"></div>

                    <div className="text-center mb-10">
                        {step === 'credentials' ? (
                            <div className="mx-auto h-20 w-20 mb-6 rounded-[1.25rem] shadow-[0_0_30px_rgba(99,102,241,0.3)] relative overflow-hidden ring-1 ring-white/10">
                                <img src="/img/af-logo.png" alt="AetherFlow Logo" className="w-full h-full object-cover scale-[1.35]" />
                            </div>
                        ) : (
                            <div className="mx-auto h-16 w-16 mb-6 rounded-2xl bg-gradient-to-br from-indigo-500 via-blue-600 to-indigo-800 flex items-center justify-center shadow-[0_0_30px_rgba(99,102,241,0.3)] relative overflow-hidden">
                                <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPgo8cmVjdCB3aWR0aD0iOCIgaGVpZ2h0PSI4IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMSIvPgo8L3N2Zz4=')] opacity-30 mix-blend-overlay"></div>
                                <Fingerprint className="text-white w-8 h-8 opacity-90 drop-shadow-md" />
                            </div>
                        )}
                        <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                            {isSetup ? 'Initialize Nexus' : (step === 'credentials' ? 'AetherFlow' : 'Verify Identity')}
                        </h1>
                        <p className="text-slate-400 text-sm mt-2 font-medium">
                            {isSetup ? 'Create primary administrative context' : (step === 'credentials' ? 'Welcome to the Aether' : 'Multi-factor authentication required')}
                        </p>
                    </div>

                    {error && (
                        <div className="mb-6 p-3 bg-red-500/10 border border-red-500/30 rounded-xl flex gap-3 text-red-200 text-sm">
                            <Info size={18} className="text-red-400 mt-0.5 shrink-0" />
                            <p className="leading-snug">{error}</p>
                        </div>
                    )}

                    {step === 'credentials' && (
                        <form onSubmit={handleLogin} className="space-y-6">
                            <div className="space-y-4">
                                <div className="relative">
                                    <input
                                        type="text"
                                        placeholder={isSetup ? 'Choose administrative operator ID' : 'Username'}
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        required
                                        autoFocus
                                        className="glass-input w-full px-4 py-3 pl-11 !text-sm font-medium"
                                    />
                                    <ShieldCheck size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
                                </div>
                                <div className="relative">
                                    <input
                                        type="password"
                                        placeholder={isSetup ? 'Establish cryptographic key (min 6)' : 'Password'}
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        minLength={isSetup ? 6 : 1}
                                        className="glass-input w-full px-4 py-3 pl-11 !text-sm font-medium"
                                    />
                                    <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={isLoading}
                                className="glass-button-primary w-full py-3.5 flex items-center justify-center gap-2 font-semibold tracking-wide disabled:opacity-50"
                            >
                                <LogIn size={18} className={isLoading ? "animate-pulse" : ""} />
                                {isLoading ? 'Authenticating...' : (isSetup ? 'Initialize Identity' : 'Unlock the Aether')}
                            </button>
                        </form>
                    )}

                    {step === 'mfa_challenge' && (
                        <form onSubmit={handleMfaSubmit} className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
                            <div className="flex justify-between gap-2 px-1">
                                {mfaCode.map((val, i) => (
                                    <input
                                        key={i}
                                        ref={mfaRefs[i]}
                                        type="text"
                                        maxLength={1}
                                        value={val}
                                        onChange={(e) => handleMfaChange(i, e.target.value)}
                                        onKeyDown={(e) => handleMfaKeyDown(i, e)}
                                        onPaste={handlePaste}
                                        className="glass-input w-12 h-14 text-center text-xl font-bold font-mono !px-0 focus:ring-2 focus:ring-indigo-500"
                                    />
                                ))}
                            </div>

                            <div className="space-y-4">
                                <button
                                    type="submit"
                                    disabled={isLoading || mfaCode.join('').length !== 6}
                                    className="glass-button-primary w-full py-3.5 flex items-center justify-center gap-2 font-semibold tracking-wide disabled:opacity-50"
                                >
                                    {isLoading ? 'Verifying Context...' : 'Authorize Action'}
                                    {!isLoading && <ArrowRight size={18} />}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setStep('credentials')}
                                    className="w-full text-center text-slate-500 hover:text-slate-300 text-sm font-medium transition-colors"
                                >
                                    Cancel and return
                                </button>
                            </div>
                        </form>
                    )}

                    {step === 'credentials' && (
                        <div className="mt-8 pt-6 border-t border-white/5 relative">
                            <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 bg-slate-950/50 backdrop-blur-md text-[10px] font-semibold text-slate-500 tracking-widest uppercase rounded-full whitespace-nowrap">
                                External Providers
                            </div>
                            <button
                                type="button"
                                onClick={() => login()}
                                className="glass-button w-full py-3 mt-2 text-sm font-semibold flex items-center justify-center gap-2 text-slate-200"
                            >
                                <Sparkles size={16} className="text-indigo-400" />
                                Authenticate via OIDC Core
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
