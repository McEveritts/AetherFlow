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
            case 'critical': return <AlertTriangle size={12} className="text-red-400" />;
            case 'stable': return <Shield size={12} className="text-emerald-400" />;
            case 'decreasing': return <TrendingUp size={12} className="text-blue-400 rotate-180" />;
            default: return <Shield size={12} className="text-slate-500" />;
        }
    };

    const trendColor = (trend: string) => {
        switch (trend) {
            case 'increasing': return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
            case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
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
        switch (metricType) {
            case 'cpu':
                return metricsHistory.map(s => Number(s.cpu_avg) || 0);
            case 'memory':
                return metricsHistory.map(s => {
                    const total = Number(s.mem_total_gb) || 0;
                    const used = Number(s.mem_used_gb) || 0;
                    return total > 0 ? (used / total) * 100 : used;
                });
            case 'disk':
                return metricsHistory.map(s => {
                    const read = Number(s.disk_read_bps) || 0;
                    const write = Number(s.disk_write_bps) || 0;
                    return (read + write) / 1024;
                });
            case 'network':
                return metricsHistory.map(s => {
                    const rx = Number(s.net_rx_bytes) || 0;
                    const tx = Number(s.net_tx_bytes) || 0;
                    return (rx + tx) / 1024;
                });
        }
    };

    return (
        <div className="glass-card rounded-2xl p-6 relative overflow-hidden">
            <div className="absolute bottom-0 left-0 w-[300px] h-[300px] bg-purple-500/5 rounded-full blur-[80px] pointer-events-none -translate-x-1/3 translate-y-1/3"></div>

            <div className="flex items-center justify-between mb-5 relative z-10">
                <div className="flex items-center gap-3">
                    <div className="h-9 w-9 bg-purple-500/20 rounded-xl flex items-center justify-center border border-purple-500/30">
                        <BrainCircuit size={18} className="text-purple-400" />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-slate-200">Resource Insights</h3>
                        <p className="text-[10px] text-slate-500">30-day predictive analysis</p>
                    </div>
                </div>
                <button
                    onClick={analyze}
                    disabled={isAnalyzing}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-600/50 text-white text-xs font-bold rounded-lg transition-all flex items-center gap-1.5"
                >
                    {isAnalyzing ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                    {isAnalyzing ? 'Analyzing...' : 'Run Analysis'}
                </button>
            </div>

            {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 flex items-center gap-2 relative z-10 mb-3">
                    <AlertTriangle size={14} /> {error}
                </div>
            )}

            {report && (
                <div className="space-y-4 relative z-10">
                    {/* Trend Badges */}
                    <div className="grid grid-cols-2 gap-2">
                        {[
                            { label: 'CPU', trend: report.cpu_trend, type: 'cpu' as const },
                            { label: 'Memory', trend: report.memory_trend, type: 'memory' as const },
                            { label: 'Disk I/O', trend: report.disk_io_trend, type: 'disk' as const },
                            { label: 'Network', trend: report.network_trend, type: 'network' as const },
                        ].map(({ label, trend, type }) => (
                            <div key={label} className="bg-slate-900/50 rounded-lg p-3 border border-white/5 flex flex-col gap-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-slate-400">{label}</span>
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

                    {/* Bottleneck */}
                    <div className="flex items-center justify-between bg-slate-900/30 rounded-lg p-3 border border-white/[0.03]">
                        <span className="text-xs text-slate-400">Predicted Bottleneck</span>
                        <span className={`text-sm font-bold uppercase ${bottleneckColor(report.predicted_bottleneck)}`}>
                            {report.predicted_bottleneck}
                        </span>
                    </div>

                    {/* Confidence */}
                    <div>
                        <div className="flex items-center justify-between text-xs mb-1.5">
                            <span className="text-slate-400">Confidence</span>
                            <span className="text-purple-400 font-bold">{(report.confidence_score * 100).toFixed(0)}%</span>
                        </div>
                        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all" style={{ width: `${report.confidence_score * 100}%` }} />
                        </div>
                    </div>

                    {/* Warnings */}
                    {report.warnings?.length > 0 && (
                        <div className="space-y-1.5">
                            {report.warnings.map((w, i) => (
                                <div key={i} className="flex items-start gap-2 text-xs text-amber-400 bg-amber-500/5 rounded-lg p-2 border border-amber-500/10">
                                    <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                                    <span>{w}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Expand/Collapse */}
                    <button
                        onClick={() => setExpanded(!expanded)}
                        className="w-full text-xs text-slate-400 hover:text-slate-300 flex items-center justify-center gap-1 py-1"
                    >
                        {expanded ? <><ChevronUp size={14} /> Hide Details</> : <><ChevronDown size={14} /> Show Details</>}
                    </button>

                    {expanded && (
                        <div className="space-y-3 animate-fade-in">
                            {/* Summary */}
                            <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/30 rounded-lg p-3 border border-white/[0.03]">
                                {report.trend_summary}
                            </p>

                            {/* Recommendations */}
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
                <p className="text-xs text-slate-500 text-center py-4 relative z-10">
                    Click Run Analysis to get 30-day resource trend predictions
                </p>
            )}
        </div>
    );
}
