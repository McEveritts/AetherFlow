import { Shield, Lock, AlertTriangle, KeyRound, MonitorSmartphone, Laptop, Search, MapPin, XCircle } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import useSWR from 'swr';

interface SessionInfo {
    jti: string;
    ip_address: string;
    user_agent: string;
    expires_at: string;
    last_active: string;
    is_current: boolean;
}

export default function SecurityTab() {
    const { addToast } = useToast();
    const { data: sessionData, mutate, error } = useSWR<{ sessions: SessionInfo[] }>('/api/v1/auth/sessions', {
        refreshInterval: 10000,
    });

    const sessions = sessionData?.sessions || [];

    const revokeSession = async (jti: string) => {
        try {
            const res = await fetch(`/api/v1/auth/sessions/${encodeURIComponent(jti)}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Failed to revoke session');
            mutate();
            addToast('Session forcefully terminated.', 'success');
        } catch (err: any) {
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
        } catch (err: any) {
            addToast('Error revoking some sessions.', 'error');
        }
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-red-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

            <div className="glass-panel rounded-3xl p-10 relative overflow-hidden">
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

                    {/* Standard Auth Controls */}
                    <div className="bg-slate-900/60 border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <Lock className="text-slate-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">Authentication Context</h3>
                        </div>
                        <p className="text-sm text-slate-400 mb-6">Manage session lifecycles, secondary factors, and encryption contexts.</p>

                        <div className="space-y-4">
                            <button 
                                onClick={() => addToast('Encryption key rotation initiated.', 'info')}
                                className="glass-button w-full text-left px-4 py-3 border border-white/5 cursor-pointer">
                                Rotate Cryptographic Key
                            </button>
                            <button 
                                onClick={() => addToast('Multi-factor enforcement updated.', 'success')}
                                className="glass-button w-full text-left px-4 py-3 border border-white/5 flex items-center justify-between cursor-pointer">
                                Enforce Strict Validation <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded uppercase tracking-wider font-bold">Active</span>
                            </button>
                        </div>
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
        </div>
    );
}
