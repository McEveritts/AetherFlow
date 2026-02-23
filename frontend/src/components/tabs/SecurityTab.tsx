import { Shield, Lock, AlertTriangle, KeyRound } from 'lucide-react';

export default function SecurityTab() {
    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-red-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden">
                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <Shield size={24} className="text-red-400" />
                    Security & Access Control
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <Lock className="text-slate-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">Authentication</h3>
                        </div>
                        <p className="text-sm text-slate-400 mb-6">Manage session timeouts, multi-factor authentication, and API tokens.</p>

                        <div className="space-y-4">
                            <button className="w-full text-left px-4 py-3 bg-white/5 hover:bg-white/10 rounded-xl text-sm font-semibold text-slate-300 transition-colors border border-white/5">
                                Change Password
                            </button>
                            <button className="w-full text-left px-4 py-3 bg-white/5 hover:bg-white/10 rounded-xl text-sm font-semibold text-slate-300 transition-colors border border-white/5 flex items-center justify-between">
                                Enforce 2FA <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded uppercase tracking-wider">Enabled</span>
                            </button>
                        </div>
                    </div>

                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <KeyRound className="text-slate-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">API Access</h3>
                        </div>
                        <p className="text-sm text-slate-400 mb-6">Tokens allowing external scripts to interact with the AetherFlow API.</p>

                        <button className="w-full px-4 py-3 bg-indigo-500 hover:bg-indigo-400 text-white rounded-xl text-sm font-bold shadow-lg shadow-indigo-500/20 transition-all text-center">
                            Generate New Token
                        </button>
                    </div>

                    <div className="md:col-span-2 bg-red-500/5 border border-red-500/20 rounded-2xl p-6 mt-4">
                        <div className="flex gap-4">
                            <AlertTriangle className="text-red-400 shrink-0" size={24} />
                            <div>
                                <h3 className="text-lg font-bold text-slate-200 mb-2">Danger Zone</h3>
                                <p className="text-sm text-slate-400 mb-4">Actions here can permanently alter or destroy access to your dashboard.</p>
                                <button className="px-6 py-2.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 rounded-lg text-sm font-bold transition-all">
                                    Revoke All Sessions
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
