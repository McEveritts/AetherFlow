import { BrainCircuit, TrendingUp, AlertTriangle, Shield, Loader2, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';
import { useState, useEffect } from 'react';
import { apiFetch } from '@/lib/fetcher';
import Sparkline from '@/components/charts/Sparkline';

interface PredictionReport {
    trend_summary: string;
    cpu_trend: string;
    memory_trend: string;
    disk_io_trend: string;
    network_trend: string;
    warnings: string[];
    recommendations: string[];
    predicted_bottleneck: string;
    confidence_score: number;
}

interface MetricsSnapshot {
    id: number;
    timestamp: string;
    cpu_avg: number;
    mem_used_gb: number;
    mem_total_gb: number;
    disk_read_bps: number;
    disk_write_bps: number;
    net_rx_bytes: number;
    net_tx_bytes: number;
    load_avg_1: number;
    active_conns: number;
}

export default function PredictionsCard() {
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [report, setReport] = useState<PredictionReport | null>(null);
    const [metricsHistory, setMetricsHistory] = useState<MetricsSnapshot[]>([]);
    const [error, setError] = useState('');
    const [expanded, setExpanded] = useState(false);

    useEffect(() => {
        let isMounted = true;
        const fetchInitialTelemetry = async () => {
            try {
                const [predRes, histRes] = await Promise.allSettled([
                    apiFetch('/api/v1/admin/ai/predictions'),
                    apiFetch('/api/v1/admin/ai/predictions/history?days=30')
                ]);
                if (!isMounted) return;
                if (predRes.status === 'fulfilled' && predRes.value.ok) {
                    const data = await predRes.value.json();
                    if (data && data.trend_summary) {
                        setReport(data);
                    }
                }
                if (histRes.status === 'fulfilled' && histRes.value.ok) {
                    const histData = await histRes.value.json();
                    if (Array.isArray(histData)) {
                        setMetricsHistory(histData);
                    }
                }
            } catch {
                // Initial load can silently wait for manual run if AI key unconfigured
            }
        };
        fetchInitialTelemetry();
        return () => { isMounted = false; };
    }, []);

    const analyze = async () => {
        setIsAnalyzing(true);
        setError('');
        try {
            const [res, histRes] = await Promise.all([
                apiFetch('/api/v1/admin/ai/predictions/analyze', { method: 'POST' }),
                apiFetch('/api/v1/admin/ai/predictions/history?days=30')
            ]);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Analysis failed');
            setReport(data);

            if (histRes.ok) {
                const histData = await histRes.json();
                if (Array.isArray(histData)) {
                    setMetricsHistory(histData);
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setIsAnalyzing(false);
        }
    };

    const trendIcon = (trend: string) => {
        switch (trend) {
            case 'increasing': return <TrendingUp size={12} className="text-amber-400" />;
            case 'critical': return <AlertTriangle size={12} className="text-rose-400" />;
            case 'stable': return <Shield size={12} className="text-emerald-400" />;
            case 'decreasing': return <TrendingUp size={12} className="text-blue-400 rotate-180" />;
            default: return <Shield size={12} className="text-slate-500" />;
        }
    };

    const trendColor = (trend: string) => {
        switch (trend) {
            case 'increasing': return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
            case 'critical': return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
            case 'stable': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
            case 'decreasing': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
            default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
        }
    };

    const bottleneckColor = (bn: string) => {
        switch (bn) {
            case 'none': return 'text-emerald-400';
            case 'cpu': case 'memory': case 'disk': case 'network': return 'text-amber-400';
            default: return 'text-slate-400';
        }
    };

    const getTrendTheme = (trend: string) => {
        switch (trend) {
            case 'increasing': return { color: '#fbbf24', gradientFrom: '#f59e0b', gradientTo: 'transparent' };
            case 'critical': return { color: '#f87171', gradientFrom: '#ef4444', gradientTo: 'transparent' };
            case 'stable': return { color: '#34d399', gradientFrom: '#10b981', gradientTo: 'transparent' };
            case 'decreasing': return { color: '#60a5fa', gradientFrom: '#3b82f6', gradientTo: 'transparent' };
            default: return { color: '#94a3b8', gradientFrom: '#64748b', gradientTo: 'transparent' };
        }
    };

    const getSparklineData = (metricType: 'cpu' | 'memory' | 'disk' | 'network'): number[] => {
        if (!metricsHistory || metricsHistory.length === 0) {
            return [0, 0];
        }
        const roundTwo = (v: number) => (Number.isFinite(v) ? Number(v.toFixed(2)) : 0);
        switch (metricType) {
            case 'cpu':
                return metricsHistory.map(s => roundTwo(Number(s.cpu_avg) || 0));
            case 'memory':
                return metricsHistory.map(s => {
                    const total = Number(s.mem_total_gb) || 0;
                    const used = Number(s.mem_used_gb) || 0;
                    return roundTwo(total > 0 ? (used / total) * 100 : used);
                });
            case 'disk':
                return metricsHistory.map(s => {
                    const read = Number(s.disk_read_bps) || 0;
                    const write = Number(s.disk_write_bps) || 0;
                    return roundTwo((read + write) / 1024);
                });
            case 'network':
                return metricsHistory.map(s => {
                    const rx = Number(s.net_rx_bytes) || 0;
                    const tx = Number(s.net_tx_bytes) || 0;
                    return roundTwo((rx + tx) / 1024);
                });
        }
    };

    return (
        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 relative overflow-hidden flex flex-col justify-between h-full">
            <div>
                <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-white/[0.06] relative z-10">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 bg-purple-500/10 rounded-lg flex items-center justify-center border border-purple-500/20 text-purple-400 shrink-0">
                            <BrainCircuit size={16} />
                        </div>
                        <div>
                            <h3 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Resource Insights</h3>
                            <p className="text-[11px] text-slate-500 mt-1">30-day predictive capacity &amp; saturation model</p>
                        </div>
                    </div>
                    <button
                        onClick={analyze}
                        disabled={isAnalyzing}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-600/50 text-white text-xs font-bold rounded-xl transition-all flex items-center gap-1.5 shadow-lg shadow-purple-500/20"
                    >
                        {isAnalyzing ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
                        {isAnalyzing ? 'Analyzing...' : 'Run Analysis'}
                    </button>
                </div>

                {error && (
                    <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-400 flex items-center gap-2 relative z-10 mb-3">
                        <AlertTriangle size={14} /> {error}
                    </div>
                )}

                {report && (
                    <div className="space-y-3.5 relative z-10">
                        {/* Trend Badges */}
                        <div className="grid grid-cols-2 gap-2.5">
                            {[
                                { label: 'CPU', trend: report.cpu_trend, type: 'cpu' as const },
                                { label: 'Memory', trend: report.memory_trend, type: 'memory' as const },
                                { label: 'Disk I/O', trend: report.disk_io_trend, type: 'disk' as const },
                                { label: 'Network', trend: report.network_trend, type: 'network' as const },
                            ].map(({ label, trend, type }) => (
                                <div key={label} className="bg-black/30 rounded-xl p-3 border border-white/[0.04] flex flex-col gap-2.5">
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs font-semibold text-slate-300">{label}</span>
                                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase border flex items-center gap-1 ${trendColor(trend)}`}>
                                            {trendIcon(trend)}
                                            {trend}
                                        </span>
                                    </div>
                                    <div className="h-8">
                                        <Sparkline
                                            data={getSparklineData(type)}
                                            height={32}
                                            color={getTrendTheme(trend).color}
                                            gradientFrom={getTrendTheme(trend).gradientFrom}
                                            gradientTo={getTrendTheme(trend).gradientTo}
                                            showArea={true}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Bottleneck & Confidence Row */}
                        <div className="grid grid-cols-2 gap-2.5">
                            <div className="flex items-center justify-between bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04]">
                                <span className="text-[11px] font-medium text-slate-400">Bottleneck</span>
                                <span className={`text-xs font-mono font-bold uppercase ${bottleneckColor(report.predicted_bottleneck)}`}>
                                    {report.predicted_bottleneck}
                                </span>
                            </div>
                            <div className="bg-black/30 rounded-xl px-3.5 py-2.5 border border-white/[0.04] flex flex-col justify-center">
                                <div className="flex items-center justify-between text-[11px] mb-1">
                                    <span className="text-slate-400">Confidence</span>
                                    <span className="text-purple-400 font-mono font-bold">{(report.confidence_score * 100).toFixed(0)}%</span>
                                </div>
                                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all" style={{ width: `${report.confidence_score * 100}%` }} />
                                </div>
                            </div>
                        </div>

                        {/* Warnings */}
                        {report.warnings?.length > 0 && (
                            <div className="space-y-1.5">
                                {report.warnings.map((w, i) => (
                                    <div key={i} className="flex items-start gap-2 text-xs text-amber-300/90 bg-amber-500/[0.07] rounded-xl p-2.5 border border-amber-500/15">
                                        <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-400" />
                                        <span className="leading-relaxed">{w}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Expand/Collapse */}
                        <button
                            onClick={() => setExpanded(!expanded)}
                            className="w-full text-xs font-semibold text-slate-400 hover:text-slate-200 flex items-center justify-center gap-1 py-1.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.04] border border-white/[0.04] transition-colors"
                        >
                            {expanded ? <><ChevronUp size={14} /> Hide Forecast Details</> : <><ChevronDown size={14} /> Show Forecast Details</>}
                        </button>

                        {expanded && (
                            <div className="space-y-3 animate-fade-in">
                                <p className="text-xs text-slate-300 leading-relaxed bg-black/30 rounded-xl p-3 border border-white/[0.04]">
                                    {report.trend_summary}
                                </p>

                                {report.recommendations?.length > 0 && (
                                    <div className="space-y-1.5">
                                        <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Recommendations</p>
                                        {report.recommendations.map((r, i) => (
                                            <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                                                <BrainCircuit size={12} className="text-purple-400 mt-0.5 shrink-0" />
                                                <span>{r}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {!report && !error && !isAnalyzing && (
                    <div className="bg-black/30 border border-white/[0.04] rounded-xl p-6 text-center my-2">
                        <BrainCircuit size={24} className="mx-auto text-purple-400/50 mb-2" />
                        <p className="text-xs font-semibold text-slate-300">Predictive Telemetry Standby</p>
                        <p className="text-[11px] text-slate-500 mt-1">
                            Run analysis to evaluate 30-day CPU, RAM, Disk I/O, and Network saturation trajectories.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
}
