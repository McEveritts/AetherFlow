import { useEffect, useRef } from 'react';
import useSWR from 'swr';
import { Terminal, Loader2, Pause, Play, Download, Sparkles, AlertCircle, Wrench, CheckCircle, XCircle } from 'lucide-react';
import { Modal } from '@/components/ui/Modal';
import { apiFetch } from '@/lib/fetcher';
import { useState } from 'react';
import { useToast } from '@/contexts/ToastContext';

interface ServiceLogsModalProps {
    serviceName: string | null;
    onClose: () => void;
}

export default function ServiceLogsModal({ serviceName, onClose }: ServiceLogsModalProps) {
    const bottomRef = useRef<HTMLDivElement>(null);
    const { addToast } = useToast();
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [aiAnalysis, setAiAnalysis] = useState<{ rootCause: string, recommendation: string, hasError: boolean } | null>(null);
    const [showRemediationBoundary, setShowRemediationBoundary] = useState(false);

    // Using SWR to poll logs every 2 seconds
    const { data: logs, error, isLoading, mutate } = useSWR<{ logs: string[] }>(
        serviceName ? `/api/v1/admin/services/${encodeURIComponent(serviceName)}/logs` : null,
        { refreshInterval: 2000, keepPreviousData: true } // Stream-like polling
    );

    // Auto-scroll to bottom on fresh logs
    useEffect(() => {
        if (logs?.logs && bottomRef.current) {
            bottomRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs?.logs]);

    if (!serviceName) return null;

    const handleDownload = () => {
        if (!logs?.logs) return;
        const blob = new Blob([logs.logs.join('\n')], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${serviceName}-stream.log`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const runAiDiagnostic = () => {
        if (!logs?.logs || logs.logs.length === 0) return;
        setIsAnalyzing(true);
        setAiAnalysis(null);
        
        // Mocking an AI diagnostic run
        setTimeout(() => {
            const hasError = logs.logs.some(l => l.toLowerCase().includes('error'));
            setAiAnalysis({
                rootCause: hasError 
                    ? "Daemon failed to bind to designated network interface. Connection reset by peer detected on local socket."
                    : "No critical errors detected. The daemon appears to be running gracefully in a stable state.",
                recommendation: hasError
                    ? `Draft a network-reset sequence for ${serviceName} to free up overlapping ports.`
                    : "No immediate remediation required.",
                hasError
            });
            setIsAnalyzing(false);
        }, 2000);
    };

    const handleApproveRemediation = () => {
        addToast(`Remediation configured for ${serviceName} and forwarded to Approval Inbox.`, 'success');
        setShowRemediationBoundary(false);
    };

    return (
        <Modal 
            isOpen={!!serviceName} 
            onClose={onClose} 
            title={`${serviceName} Daemon Matrix`}
            className="max-w-4xl w-full"
        >
            <div className="flex items-center justify-between mb-4 mt-2">
                <div className="flex items-center gap-3">
                    <span className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-widest bg-white/5 border border-white/10 px-3 py-1 rounded-lg">
                        <Terminal size={14} className="text-indigo-400" />
                        Live STDOUT / STDERR
                    </span>
                    {isLoading && <Loader2 size={14} className="animate-spin text-slate-500" />}
                </div>
                
                <div className="flex items-center gap-2">
                    <button 
                        onClick={runAiDiagnostic}
                        disabled={isAnalyzing || !logs?.logs}
                        className="flex items-center gap-2 px-3 py-1.5 text-indigo-300 hover:text-white bg-indigo-500/10 hover:bg-indigo-500/20 rounded-lg transition-colors border border-indigo-500/30 disabled:opacity-50 text-xs font-bold tracking-wide"
                        title="Run FlowAI Log Diagnostic"
                    >
                        {isAnalyzing ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                        FlowAI Auto-Debug
                    </button>
                    <div className="w-px h-6 bg-white/10 mx-1"></div>
                    <button 
                        onClick={() => mutate()}
                        className="p-1.5 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg transition-colors border border-white/5"
                        title="Force sync"
                    >
                        <Play size={14} />
                    </button>
                    <button 
                        onClick={handleDownload}
                        className="p-1.5 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg transition-colors border border-white/5"
                        title="Export Matrix"
                    >
                        <Download size={14} />
                    </button>
                </div>
            </div>

            {aiAnalysis && (
                <div className="mb-4 bg-slate-900 border border-indigo-500/30 p-4 rounded-xl shadow-[0_0_20px_rgba(99,102,241,0.05)] animate-fade-in relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 blur-3xl pointer-events-none translate-x-1/2 -translate-y-1/2"></div>
                    <div className="flex gap-3 relative z-10">
                        <div className="h-10 w-10 shrink-0 bg-indigo-500/20 border border-indigo-500/30 rounded-lg flex items-center justify-center">
                            <Sparkles size={18} className="text-indigo-400" />
                        </div>
                        <div className="flex-1">
                            <div className="flex items-center justify-between">
                                <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                                    FlowAI Diagnostic Result
                                    {aiAnalysis.rootCause.includes('No critical') ? (
                                        <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/30 tracking-wider">HEALTHY</span>
                                    ) : (
                                        <span className="text-[10px] bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded border border-amber-500/30 tracking-wider">ERROR DETECTED</span>
                                    )}
                                </h4>
                            </div>
                            <p className="text-xs text-slate-400 mt-2 font-mono leading-relaxed bg-black/20 p-2 rounded border border-white/5">
                                <span className="text-slate-500 font-sans font-semibold mb-1 block">Root Cause Pattern:</span>
                                {aiAnalysis.rootCause}
                            </p>
                            <p className="text-xs text-indigo-300 mt-2 font-medium">
                                <span className="text-slate-500 font-sans font-semibold mb-1 block">Suggested Remediation:</span>
                                {aiAnalysis.recommendation}
                            </p>
                            
                            {/* Actionable Human-In-The-Loop Boundary Hook */}
                            {aiAnalysis.hasError && (
                                <div className="mt-4 pt-3 border-t border-indigo-500/10 flex justify-end">
                                    <button
                                        onClick={() => setShowRemediationBoundary(true)}
                                        className="px-4 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-900 text-xs font-bold tracking-wide rounded-lg shadow-[0_0_15px_rgba(245,158,11,0.2)] transition-all flex items-center gap-2"
                                    >
                                        <Wrench size={14} />
                                        Review Proposed Remediation
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            <div className="bg-slate-950 border border-white/10 rounded-xl p-4 overflow-y-auto font-mono text-xs text-slate-300 relative" style={{ height: '50vh', maxHeight: '500px' }}>
                {error ? (
                    <div className="text-red-400 text-center py-10 font-sans">
                        Unable to bridge local log socket. Core daemon may be unresponsive.
                    </div>
                ) : !logs?.logs ? (
                    <div className="flex items-center justify-center py-20 text-slate-500 font-sans">
                        <Loader2 size={24} className="animate-spin mb-2 text-indigo-500/50" />
                        <span className="block w-full mt-2">Awaiting stream packets...</span>
                    </div>
                ) : logs.logs.length === 0 ? (
                    <div className="text-slate-500 text-center py-10 font-sans">
                        Stream empty. No terminal output detected for this process.
                    </div>
                ) : (
                    <div className="space-y-1 pb-4">
                        {logs.logs.map((line, idx) => {
                            // Syntax highlight basic error/warn lines
                            const isError = line.toLowerCase().includes('error') || line.toLowerCase().includes('fail');
                            const isWarn = line.toLowerCase().includes('warn');
                            const isInfo = line.toLowerCase().includes('info');

                            const colorClass = isError ? 'text-red-400' : isWarn ? 'text-amber-400' : isInfo ? 'text-emerald-400' : 'text-slate-400';
                            
                            return (
                                <div key={idx} className={`break-words ${colorClass}`}>
                                    {line}
                                </div>
                            );
                        })}
                        <div ref={bottomRef} />
                    </div>
                )}
            </div>
            
            <div className="mt-4 text-[10px] text-slate-500 font-bold uppercase tracking-widest text-center">
                Raw terminal output from isolated daemon environment. Strict scoping enforced.
            </div>

            {/* AI Remediation Approval Boundary */}
            <Modal isOpen={showRemediationBoundary} onClose={() => setShowRemediationBoundary(false)}>
                <div className="flex flex-col items-center text-center">
                    <div className="h-16 w-16 bg-amber-500/20 rounded-2xl border border-amber-500/30 flex items-center justify-center mb-6 shadow-inner">
                        <AlertCircle size={32} className="text-amber-400" />
                    </div>
                    <h3 className="text-xl font-bold text-slate-100 mb-2">Remediation Proposed</h3>
                    <p className="text-sm text-slate-400 mb-6">
                        FlowAI has drafted an executor sequence to resolve the error pattern matching <span className="text-amber-300 font-bold">"{serviceName} Socket Bind Failure"</span>. 
                        No autonomous action has occurred. 
                    </p>

                    <div className="bg-black/20 border border-white/5 rounded-xl w-full p-4 mb-6 text-left relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-2 opacity-10">
                            <Wrench size={48} />
                        </div>
                        <h4 className="text-[10px] uppercase font-bold text-slate-500 tracking-wider mb-3">Payload Preview</h4>
                        <ul className="text-sm text-slate-300 space-y-2 font-mono relative z-10 w-full">
                            <li className="flex items-start gap-2">
                                <span className="text-emerald-400 shrink-0">1.</span>
                                <span>`docker network disconnect aether ${serviceName}`</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-emerald-400 shrink-0">2.</span>
                                <span>`docker network connect aether ${serviceName}`</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-emerald-400 shrink-0">3.</span>
                                <span>`systemctl restart af-worker-${serviceName}`</span>
                            </li>
                        </ul>
                    </div>
                    
                    <div className="w-full flex gap-3">
                        <button 
                            onClick={handleApproveRemediation}
                            className="flex-1 glass-button-primary flex items-center justify-center gap-2 py-3 border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20"
                        >
                            <CheckCircle size={18} />
                            <span className="font-bold tracking-wide">FORWARD TO INBOX</span>
                        </button>
                        <button 
                            onClick={() => setShowRemediationBoundary(false)}
                            className="flex-1 glass-button flex items-center justify-center gap-2 py-3 text-slate-400 hover:text-slate-200"
                        >
                            <XCircle size={18} />
                            <span className="font-bold tracking-wide">DECLINE</span>
                        </button>
                    </div>
                </div>
            </Modal>
        </Modal>
    );
}
