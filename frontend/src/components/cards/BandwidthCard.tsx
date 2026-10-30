import { Gauge, Wifi, Zap, Loader2, CheckCircle2, AlertTriangle, ArrowUpCircle, ArrowDownCircle } from 'lucide-react';
import { useState } from 'react';
import { apiFetch } from '@/lib/fetcher';

interface BandwidthRecommendation {
    recommended_upload_kbps: number;
    recommended_download_kbps: number;
    reasoning: string;
    confidence: number;
    swarm_health: string;
    suggestions: string[];
}

export default function BandwidthCard() {
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [isApplying, setIsApplying] = useState(false);
    const [applySuccess, setApplySuccess] = useState(false);
    const [recommendation, setRecommendation] = useState<BandwidthRecommendation | null>(null);
    const [error, setError] = useState('');

    const analyze = async () => {
        setIsAnalyzing(true);
        setApplySuccess(false);
        setError('');
        try {
            const res = await apiFetch('/api/v1/admin/ai/bandwidth/analyze', { method: 'POST' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            setRecommendation(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setIsAnalyzing(false);
        }
    };

    const applyLimits = async () => {
        if (!recommendation) return;
        setIsApplying(true);
        setError('');
        setApplySuccess(false);
        try {
            const res = await apiFetch('/api/v1/admin/ai/bandwidth/apply', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    upload_kbps: recommendation.recommended_upload_kbps,
                    download_kbps: recommendation.recommended_download_kbps
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Apply failed');
            setApplySuccess(true);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Apply failed');
        } finally {
            setIsApplying(false);
        }
    };

    const healthColor = (health: string) => {
        switch (health) {
            case 'healthy': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
            case 'congested': return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
            case 'underutilized': return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
            default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
        }
    };

    const formatKBps = (kbps: number) => {
        if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} MB/s`;
        return `${kbps} KB/s`;
    };

    return (
        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 relative overflow-hidden flex flex-col justify-between h-full">
            <div>
                <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-white/[0.06] relative z-10">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 bg-cyan-500/10 rounded-lg flex items-center justify-center border border-cyan-500/20 text-cyan-400 shrink-0">
                            <Gauge size={16} />
                        </div>
                        <div>
                            <h3 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Bandwidth Optimizer</h3>
                            <p className="text-[11px] text-slate-500 mt-1">AI-assisted swarm &amp; peering rate tuning</p>
                        </div>
                    </div>
                    <button
                        onClick={analyze}
                        disabled={isAnalyzing}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-xs font-bold rounded-xl transition-all flex items-center gap-1.5 shadow-lg shadow-cyan-500/20"
                    >
                        {isAnalyzing ? <Loader2 size={13} className="animate-spin" /> : <Zap size={13} />}
                        {isAnalyzing ? 'Analyzing...' : 'Analyze'}
                    </button>
                </div>

                {error && (
                    <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-400 flex items-center gap-2 relative z-10 mb-3">
                        <AlertTriangle size={14} /> {error}
                    </div>
                )}

                {recommendation && (
                    <div className="space-y-3.5 relative z-10">
                        {/* Speed Recommendations */}
                        <div className="grid grid-cols-2 gap-2.5">
                            <div className="bg-black/30 rounded-xl p-3.5 border border-white/[0.04]">
                                <div className="flex items-center gap-1.5 text-emerald-400 mb-1.5">
                                    <ArrowDownCircle size={13} />
                                    <span className="text-[10px] uppercase tracking-wider font-bold">Download Ceiling</span>
                                </div>
                                <p className="text-lg font-extrabold text-slate-100 font-mono tabular-nums">{formatKBps(recommendation.recommended_download_kbps)}</p>
                            </div>
                            <div className="bg-black/30 rounded-xl p-3.5 border border-white/[0.04]">
                                <div className="flex items-center gap-1.5 text-blue-400 mb-1.5">
                                    <ArrowUpCircle size={13} />
                                    <span className="text-[10px] uppercase tracking-wider font-bold">Upload Ceiling</span>
                                </div>
                                <p className="text-lg font-extrabold text-slate-100 font-mono tabular-nums">{formatKBps(recommendation.recommended_upload_kbps)}</p>
                            </div>
                        </div>

                        {/* Swarm Health & Confidence Row */}
                        <div className="grid grid-cols-2 gap-2.5">
                            <div className="flex items-center justify-between bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04]">
                                <div className="flex items-center gap-1.5">
                                    <Wifi size={13} className="text-slate-400" />
                                    <span className="text-[11px] font-medium text-slate-400">Swarm Health</span>
                                </div>
                                <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold border uppercase ${healthColor(recommendation.swarm_health)}`}>
                                    {recommendation.swarm_health}
                                </span>
                            </div>

                            <div className="bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04] flex flex-col justify-center">
                                <div className="flex items-center justify-between text-[11px] mb-1">
                                    <span className="text-slate-400">Confidence</span>
                                    <span className="text-cyan-400 font-mono font-bold">{(recommendation.confidence * 100).toFixed(0)}%</span>
                                </div>
                                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all" style={{ width: `${recommendation.confidence * 100}%` }} />
                                </div>
                            </div>
                        </div>

                        {/* Reasoning */}
                        <p className="text-xs text-slate-300 leading-relaxed bg-black/30 rounded-xl p-3 border border-white/[0.04]">
                            {recommendation.reasoning}
                        </p>

                        {/* Suggestions */}
                        {recommendation.suggestions?.length > 0 && (
                            <div className="space-y-1.5">
                                {recommendation.suggestions.map((s, i) => (
                                    <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                                        <CheckCircle2 size={13} className="text-cyan-400 mt-0.5 shrink-0" />
                                        <span className="leading-relaxed">{s}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {applySuccess && (
                            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-xs text-emerald-400 flex items-center gap-2">
                                <CheckCircle2 size={14} /> Limits applied successfully to daemon
                            </div>
                        )}

                        <button
                            onClick={applyLimits}
                            disabled={isApplying || applySuccess}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-600/50 text-white text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-1.5 shadow-lg shadow-emerald-500/20"
                        >
                            {isApplying ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                            {isApplying ? 'Applying Limits...' : applySuccess ? 'Applied' : 'Apply Recommendations'}
                        </button>
                    </div>
                )}

                {!recommendation && !error && !isAnalyzing && (
                    <div className="bg-black/30 border border-white/[0.04] rounded-xl p-6 text-center my-2">
                        <Gauge size={24} className="mx-auto text-cyan-400/50 mb-2" />
                        <p className="text-xs font-semibold text-slate-300">Swarm Rate Optimizer Ready</p>
                        <p className="text-[11px] text-slate-500 mt-1">
                            Analyze current NIC saturation, disk write queues, and peer counts to calculate optimal transfer ceilings.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
}
