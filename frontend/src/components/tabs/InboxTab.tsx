import { useState } from 'react';
import { Mail, CheckCircle, XCircle, AlertTriangle, ShieldAlert, Code, ServerCrash } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';

interface PendingAction {
    id: string;
    intent: string;
    source: 'FlowAI' | 'Marketplace' | 'System';
    timestamp: string;
    impactLevel: 'low' | 'medium' | 'high' | 'critical';
    blastRadius: string;
    payloadDiff?: string;
}

const MOCK_ACTIONS: PendingAction[] = [
    {
        id: 'req_1092',
        intent: 'Automated remediation: Restart crashing NGINX reverse-proxy container',
        source: 'FlowAI',
        timestamp: '2 mins ago',
        impactLevel: 'medium',
        blastRadius: 'Temporary disruption of external web traffic mapping (approx. 5-10 seconds drop).',
    },
    {
        id: 'req_1093',
        intent: 'Marketplace Install: Nextcloud Stack',
        source: 'Marketplace',
        timestamp: '14 mins ago',
        impactLevel: 'high',
        blastRadius: 'Provisions 3 new containers (DB, Redis, App) and modifies wildcard SSL routing rules.',
        payloadDiff: `+ Add route: cloud.aetherflow.local -> 10.0.0.94:80
+ Volume mount: /mnt/aether_pool/nextcloud_data
- Remove route fallback (default)`
    },
    {
        id: 'req_1094',
        intent: 'Emergency Core Patch: CVE-2026-X1192',
        source: 'System',
        timestamp: '1 hr ago',
        impactLevel: 'critical',
        blastRadius: 'Requires full host orbital reboot. All services will go offline for 60-120 seconds.',
    }
];

export default function InboxTab() {
    const { addToast } = useToast();
    const [actions, setActions] = useState<PendingAction[]>(MOCK_ACTIONS);

    const handleApprove = (id: string, intent: string) => {
        setActions(prev => prev.filter(a => a.id !== id));
        addToast(`Execution authorized: ${intent}`, 'success');
    };

    const handleReject = (id: string) => {
        setActions(prev => prev.filter(a => a.id !== id));
        addToast('Action rejected. Execution halted.', 'info');
    };

    const impactColors = {
        low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
        medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
        high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
        critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-indigo-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

            <div className="glass-panel rounded-3xl p-6 md:p-10 relative overflow-hidden">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <Mail size={24} className="text-indigo-400" />
                        Action Approval Inbox
                        {actions.length > 0 && (
                            <span className="bg-indigo-500 text-white text-sm font-bold px-2 py-0.5 rounded-full">
                                {actions.length}
                            </span>
                        )}
                    </h2>
                    <p className="text-sm text-slate-400">Strict operator consent required.</p>
                </div>

                <div className="space-y-6 relative z-10">
                    {actions.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                            <CheckCircle size={48} className="text-emerald-500/20 mb-4" />
                            <h3 className="text-lg font-bold text-slate-300">Queue Empty</h3>
                            <p className="text-sm">No pending automated actions require your authorization.</p>
                        </div>
                    ) : (
                        actions.map(action => (
                            <div key={action.id} className="bg-slate-900/60 border border-white/10 rounded-2xl p-6 transition-all hover:border-indigo-500/30">
                                <div className="flex flex-col lg:flex-row justify-between items-start gap-6">
                                    
                                    {/* Left Content Area */}
                                    <div className="flex-1 w-full space-y-4">
                                        <div className="flex flex-wrap items-center gap-3">
                                            <span className="text-xs font-bold uppercase tracking-wider text-slate-400 border border-white/10 px-2 py-1 rounded bg-white/5">
                                                {action.source}
                                            </span>
                                            <span className="text-xs text-slate-500">{action.timestamp}</span>
                                            <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded border ${impactColors[action.impactLevel]} flex items-center gap-1`}>
                                                {action.impactLevel === 'critical' && <ShieldAlert size={12} />}
                                                {action.impactLevel} Impact Radius
                                            </span>
                                        </div>

                                        <h3 className="text-lg font-bold text-slate-200">{action.intent}</h3>

                                        <div className="bg-white/5 rounded-xl p-4 border border-white/5">
                                            <div className="text-xs font-bold text-slate-400 mb-1 flex items-center gap-2 uppercase tracking-wide">
                                                <AlertTriangle size={14} className="text-amber-400" /> Blast Radius
                                            </div>
                                            <p className="text-sm text-slate-300 left-border-accent">{action.blastRadius}</p>
                                        </div>

                                        {action.payloadDiff && (
                                            <div className="bg-slate-950 rounded-xl p-4 border border-white/5 overflow-x-auto">
                                                <div className="text-xs font-bold text-slate-400 mb-2 flex items-center gap-2 uppercase tracking-wide">
                                                    <Code size={14} className="text-indigo-400" /> Diff Matrix / Payload
                                                </div>
                                                <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
                                                    {action.payloadDiff.split('\n').map((line, idx) => (
                                                        <div key={idx} className={`${line.startsWith('+') ? 'text-emerald-400' : line.startsWith('-') ? 'text-red-400' : ''}`}>
                                                            {line}
                                                        </div>
                                                    ))}
                                                </pre>
                                            </div>
                                        )}
                                    </div>

                                    {/* Right Action Area */}
                                    <div className="flex flex-row lg:flex-col gap-3 w-full lg:w-48 shrink-0">
                                        <button 
                                            onClick={() => handleApprove(action.id, action.intent)}
                                            className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 px-4 shadow-[0_0_15px_rgba(34,197,94,0.2)] hover:shadow-[0_0_20px_rgba(34,197,94,0.4)] border-emerald-500/50 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                                        >
                                            <CheckCircle size={18} />
                                            <span className="font-bold tracking-wide">AUTHORIZE</span>
                                        </button>
                                        <button 
                                            onClick={() => handleReject(action.id)}
                                            className="flex-1 glass-button flex items-center justify-center gap-2 py-3 px-4 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50"
                                        >
                                            <XCircle size={18} />
                                            <span className="font-bold tracking-wide">REJECT</span>
                                        </button>
                                    </div>
                                    
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}
