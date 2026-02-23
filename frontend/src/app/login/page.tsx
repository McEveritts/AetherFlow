'use client';

import { useAuth } from '@/contexts/AuthContext';
import { Sparkles, KeyRound, LogIn } from 'lucide-react';
import { FormEvent, useState, useEffect } from 'react';

export default function LoginPage() {
    const { login, loginLocal } = useAuth();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [isSetup, setIsSetup] = useState(false);

    useEffect(() => {
        fetch('/api/auth/setup/check')
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
            const endpoint = isSetup ? '/api/auth/setup' : '/api/auth/login';
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username: username.trim(), password: password.trim() })
            });

            const data = await res.json();

            if (res.ok) {
                loginLocal();
            } else {
                setError(data.error || 'Login failed');
            }
        } catch (_err) {
            setError('Connection error. Is the backend running?');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center relative overflow-hidden selection:bg-indigo-500/30">
            {/* Background ambient lighting */}
            <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
                <div className="absolute top-1/4 left-1/4 w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px]"></div>
                <div className="absolute bottom-1/4 right-1/4 w-[40%] h-[40%] bg-blue-900/10 rounded-full blur-[100px]"></div>
            </div>

            <div className="w-full max-w-md p-8 relative z-10">
                <div className="bg-slate-950/80 backdrop-blur-2xl border border-white/10 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
                    {/* Header Glow */}
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>

                    <div className="text-center mb-10">
                        <div className="mx-auto h-16 w-16 mb-6 rounded-2xl bg-gradient-to-br from-indigo-500 via-blue-600 to-indigo-800 flex items-center justify-center shadow-[0_0_30px_rgba(99,102,241,0.4)] relative overflow-hidden">
                            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPgo8cmVjdCB3aWR0aD0iOCIgaGVpZ2h0PSI4IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMSIvPgo8L3N2Zz4=')] opacity-30 mix-blend-overlay"></div>
                            <span className="font-extrabold text-white text-3xl tracking-tighter mix-blend-screen drop-shadow-md">A</span>
                        </div>
                        <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                            {isSetup ? 'Create Admin Account' : 'Access Nexus'}
                        </h1>
                        <p className="text-slate-400 text-sm mt-2">
                            {isSetup ? 'Set up your first admin account' : 'AetherFlow Unified Dashboard'}
                        </p>
                    </div>

                    {error && (
                        <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm text-center">
                            {error}
                        </div>
                    )}

                    <form onSubmit={handleLogin} className="space-y-6">
                        <div className="space-y-4">
                            <div className="relative">
                                <input
                                    type="text"
                                    placeholder={isSetup ? 'Choose a Username' : 'Username'}
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    required
                                    className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 pl-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 focus:bg-white/[0.02] transition-colors"
                                />
                                <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                            </div>
                            <div className="relative">
                                <input
                                    type="password"
                                    placeholder={isSetup ? 'Choose a Password (min 6 chars)' : 'Password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                    minLength={isSetup ? 6 : 1}
                                    className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-4 py-3 pl-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 focus:bg-white/[0.02] transition-colors"
                                />
                                <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className="w-full py-3.5 bg-indigo-500 hover:bg-indigo-400 text-white rounded-xl text-sm font-bold tracking-wide transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                        >
                            <LogIn size={16} />
                            {isLoading ? 'Unlocking...' : (isSetup ? 'Create Account & Enter' : 'Unlock the Aether')}
                        </button>
                    </form>

                    <div className="mt-8 pt-6 border-t border-white/5 relative">
                        <button
                            type="button"
                            onClick={() => login()}
                            className="w-full py-3 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 text-slate-300 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2"
                        >
                            <Sparkles size={16} className="text-indigo-400" />
                            Continue with Google OAuth
                        </button>
                        <p className="text-center text-[10px] text-slate-600 mt-3">Google OAuth requires additional configuration</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
