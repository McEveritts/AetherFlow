import { Gauge, Wifi, Zap, Loader2, CheckCircle2, AlertTriangle, ArrowUpCircle, ArrowDownCircle } from 'lucide-react';
import { useState } from 'react';

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
    const [recommendation, setRecommendation] = useState<BandwidthRecommendation | null>(null);
    const [error, setError] = useState('');

    const analyze = async () => {
        setIsAnalyzing(true);
        setError('');
        try {
            const res = await fetch('/api/ai/bandwidth/analyze', { method: 'POST' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            setRecommendation(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setIsAnalyzing(false);
        }
    };

    const healthColor = (health: string) => {
        switch (health) {
            case 'healthy': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
            case 'congested': return 'text-red-400 bg-red-500/10 border-red-500/20';
            case 'underutilized': return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
            default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
        }
    };

    const formatKBps = (kbps: number) => {
        if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} MB/s`;
        return `${kbps} KB/s`;
    };

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6 backdrop-blur-xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-cyan-500/5 rounded-full blur-[80px] pointer-events-none translate-x-1/3 -translate-y-1/3"></div>

            <div className="flex items-center justify-between mb-5 relative z-10">
                <div className="flex items-center gap-3">
                    <div className="h-9 w-9 bg-cyan-500/20 rounded-xl flex items-center justify-center border border-cyan-500/30">
                        <Gauge size={18} className="text-cyan-400" />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-slate-200">Bandwidth Optimizer</h3>
                        <p className="text-[10px] text-slate-500">AI-powered peering analysis</p>
                    </div>
                </div>
                <button
                    onClick={analyze}
                    disabled={isAnalyzing}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-xs font-bold rounded-lg transition-all flex items-center gap-1.5"
                >
                    {isAnalyzing ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
                    {isAnalyzing ? 'Analyzing...' : 'Analyze'}
                </button>
            </div>

            {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 flex items-center gap-2 relative z-10 mb-3">
                    <AlertTriangle size={14} /> {error}
                </div>
            )}

            {recommendation && (
                <div className="space-y-4 relative z-10">
                    {/* Speed Recommendations */}
                    <div className="grid grid-cols-2 gap-3">
                        <div className="bg-slate-900/50 rounded-xl p-4 border border-white/5">
                            <div className="flex items-center gap-2 text-emerald-400 mb-2">
                                <ArrowDownCircle size={14} />
                                <span className="text-[10px] uppercase tracking-wider font-bold">Download</span>
                            </div>
                            <p className="text-xl font-bold text-slate-200">{formatKBps(recommendation.recommended_download_kbps)}</p>
                        </div>
                        <div className="bg-slate-900/50 rounded-xl p-4 border border-white/5">
                            <div className="flex items-center gap-2 text-blue-400 mb-2">
                                <ArrowUpCircle size={14} />
                                <span className="text-[10px] uppercase tracking-wider font-bold">Upload</span>
                            </div>
                            <p className="text-xl font-bold text-slate-200">{formatKBps(recommendation.recommended_upload_kbps)}</p>
                        </div>
                    </div>

                    {/* Swarm Health */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <Wifi size={14} className="text-slate-400" />
                            <span className="text-xs text-slate-400">Swarm Health</span>
                        </div>
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border capitalize ${healthColor(recommendation.swarm_health)}`}>
                            {recommendation.swarm_health}
                        </span>
                    </div>

                    {/* Confidence */}
                    <div>
                        <div className="flex items-center justify-between text-xs mb-1.5">
                            <span className="text-slate-400">Confidence</span>
                            <span className="text-cyan-400 font-bold">{(recommendation.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all" style={{ width: `${recommendation.confidence * 100}%` }} />
                        </div>
                    </div>

                    {/* Reasoning */}
                    <p className="text-xs text-slate-400 leading-relaxed bg-slate-900/30 rounded-lg p-3 border border-white/[0.03]">
                        {recommendation.reasoning}
                    </p>

                    {/* Suggestions */}
                    {recommendation.suggestions?.length > 0 && (
                        <div className="space-y-1.5">
                            {recommendation.suggestions.map((s, i) => (
                                <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                                    <CheckCircle2 size={12} className="text-cyan-400 mt-0.5 shrink-0" />
                                    <span>{s}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {!recommendation && !error && !isAnalyzing && (
                <p className="text-xs text-slate-500 text-center py-4 relative z-10">
                    Click Analyze to get AI-powered bandwidth recommendations
                </p>
            )}
        </div>
    );
}
