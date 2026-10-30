import React, { useState, useEffect } from 'react';
import useSWR from 'swr';
import { Film, Play, CheckCircle, XCircle, Loader2, ArrowRightCircle, HardDrive, Sparkles, RefreshCw, Zap } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';
import PathSelector from '@/components/ui/PathSelector';
import MetadataTab from '@/components/tabs/MetadataTab';

const fetcher = (url: string) => apiFetch(url).then(res => res.json());

interface QueueItem {
    id: number;
    filePath: string;
    status: string;
    originalCodec: string;
    originalSize: number;
    newCodec: string;
    newSize: number;
    errorLog: string;
    createdAt: string;
}

interface StreamProgress {
    filePath: string;
    frame: string;
    fps: string;
    size: string;
    time: string;
    bitrate: string;
    speed: string;
    status: string;
}

function useMediaFlowStream() {
    const [progress, setProgress] = useState<StreamProgress | null>(null);

    useEffect(() => {
        let eventSource: EventSource | null = null;
        try {
            eventSource = new EventSource('/api/v1/auth/deploy/stream?appName=mediaflow_engine', { withCredentials: true });
            
            eventSource.onmessage = (event) => {
                try {
                    const data: StreamProgress = JSON.parse(event.data);
                    setProgress(data);
                } catch {
                    // ignore ping or progress formatting variation
                }
            };
        } catch (err) {
            console.error("SSE stream error", err);
        }

        return () => {
            if (eventSource) {
                eventSource.close();
            }
        };
    }, []);

    return progress;
}

const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function MediaFlowTab() {
    const [activeSection, setActiveSection] = useState<'transcode' | 'metadata'>('transcode');
    const { data: queue, error, isLoading, isValidating, mutate } = useSWR<QueueItem[]>('/api/v1/admin/mediaflow/queue', fetcher);
    const progress = useMediaFlowStream();
    const [scanDir, setScanDir] = useState('/home/hdd');
    const [isScanning, setIsScanning] = useState(false);
    const { addToast } = useToast();

    const handleApprove = async (id: number) => {
        try {
            await apiFetch(`/api/v1/admin/mediaflow/approve/${id}`, {
                method: 'POST'
            });
            mutate();
            addToast('Transcode job approved and queued.', 'success');
        } catch {
            addToast('Failed to approve transcode job.', 'error');
        }
    };

    const triggerScan = async () => {
        setIsScanning(true);
        try {
            await apiFetch('/api/v1/admin/mediaflow/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ directory: scanDir })
            });
            addToast(`Background scan initiated across ${scanDir}`, 'info');
        } catch {
            addToast(`Failed to initiate scan across ${scanDir}`, 'error');
        } finally {
            setIsScanning(false);
        }
    };

    const queueList = Array.isArray(queue) ? queue : [];
    const pendingCount = queueList.filter(i => i.status === 'PENDING_APPROVAL').length;
    const completedCount = queueList.filter(i => i.status === 'COMPLETED').length;
    const totalSavedBytes = queueList
        .filter(i => i.status === 'COMPLETED' && i.originalSize > i.newSize)
        .reduce((acc, i) => acc + (i.originalSize - i.newSize), 0);

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Unified FlowAI Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        {activeSection === 'transcode' ? <Film size={20} /> : <Sparkles size={20} />}
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">MediaFlow Engine</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Hardware Accelerated
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                VAAPI / AMF · Live Transcode & AI Metadata
                            </span>
                        </div>
                    </div>
                </div>

                {/* Section Switcher & Controls */}
                <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1 p-1 bg-white/[0.04] border border-white/10 rounded-xl">
                        <button
                            type="button"
                            onClick={() => setActiveSection('transcode')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                activeSection === 'transcode'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Film size={13} />
                            Transcode Queue
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveSection('metadata')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                activeSection === 'metadata'
                                    ? 'bg-violet-500/20 border border-violet-500/30 text-violet-300 shadow-md shadow-violet-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Sparkles size={13} />
                            Metadata Enrichment
                        </button>
                    </div>

                    {activeSection === 'transcode' && (
                        <button
                            onClick={() => mutate()}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                            title="Refresh Queue"
                        >
                            <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                            <span>Refresh</span>
                        </button>
                    )}
                </div>
            </div>

            {activeSection === 'metadata' ? (
                <MetadataTab />
            ) : (
                <>
                    {/* Open Telemetry Metric Strip */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                            <div>
                                <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Pending Approvals</p>
                                <p className="text-2xl font-bold text-amber-400 mt-1">{pendingCount}</p>
                                <p className="text-[11px] text-slate-500 mt-0.5">Awaiting operator signoff</p>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                                <ArrowRightCircle size={20} />
                            </div>
                        </div>

                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                            <div>
                                <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Completed Jobs</p>
                                <p className="text-2xl font-bold text-emerald-400 mt-1">{completedCount}</p>
                                <p className="text-[11px] text-slate-500 mt-0.5">Transcoded & verified</p>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                                <CheckCircle size={20} />
                            </div>
                        </div>

                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                            <div>
                                <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Space Saved</p>
                                <p className="text-2xl font-bold text-slate-100 mt-1">{formatBytes(totalSavedBytes)}</p>
                                <p className="text-[11px] text-slate-500 mt-0.5">Compression reduction</p>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                                <HardDrive size={20} />
                            </div>
                        </div>

                        <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                            <div>
                                <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Hardware Engine</p>
                                <p className="text-base font-bold text-slate-100 mt-1">
                                    {progress && progress.status === 'PROCESSING' ? `${progress.speed}x Active` : 'VAAPI / AMF Standby'}
                                </p>
                                <p className="text-[11px] text-slate-500 mt-0.5">AMD / Intel Native GPU</p>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                                <Zap size={20} />
                            </div>
                        </div>
                    </div>

                    {/* Scan Trigger Bar */}
                    <div className="relative z-20 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                                <HardDrive size={16} />
                            </div>
                            <div>
                                <h3 className="text-xs font-bold text-slate-200">Library Scanner</h3>
                                <p className="text-[11px] text-slate-400">Scan filesystem to queue videos with legacy codecs for transcode optimization</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2">
                            <PathSelector
                                value={scanDir}
                                onChange={setScanDir}
                                placeholder="/home/hdd"
                                className="w-full md:w-72 text-xs"
                            />
                            <button
                                onClick={triggerScan}
                                disabled={isScanning}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-1.5 shrink-0 disabled:opacity-50"
                            >
                                {isScanning ? <Loader2 size={13} className="animate-spin" /> : <HardDrive size={13} />}
                                <span>Scan Library</span>
                            </button>
                        </div>
                    </div>

                    {/* Active Hardware Transcode */}
                    {progress && progress.status === 'PROCESSING' && (
                        <div className="rounded-2xl border border-indigo-500/30 bg-slate-900/60 backdrop-blur-xl p-5 relative z-10 overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-black/50">
                                <div className="h-full bg-indigo-500 animate-pulse w-full"></div>
                            </div>
                            <div className="flex justify-between items-center mb-3">
                                <h3 className="text-base font-bold text-white flex items-center gap-2">
                                    <Loader2 className="animate-spin text-indigo-400" size={18} />
                                    Active Hardware Transcode
                                </h3>
                                <span className="bg-indigo-500/20 text-indigo-300 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wider border border-indigo-500/30">
                                    VAAPI/AMF ACTIVE
                                </span>
                            </div>
                            <p className="text-indigo-200 text-sm font-medium mb-4 truncate" title={progress.filePath}>{progress.filePath}</p>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                <div className="bg-black/30 rounded-xl p-3 border border-white/5">
                                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-0.5">FPS</span>
                                    <span className="text-xl font-mono text-white">{progress.fps}</span>
                                </div>
                                <div className="bg-black/30 rounded-xl p-3 border border-white/5">
                                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-0.5">Speed</span>
                                    <span className="text-xl font-mono text-amber-400">{progress.speed}x</span>
                                </div>
                                <div className="bg-black/30 rounded-xl p-3 border border-white/5">
                                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-0.5">Elapsed</span>
                                    <span className="text-xl font-mono text-white">{progress.time}</span>
                                </div>
                                <div className="bg-black/30 rounded-xl p-3 border border-white/5">
                                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-0.5">Size</span>
                                    <span className="text-xl font-mono text-white">{progress.size}</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Transcode Queue Table */}
                    <div className="relative z-10 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                        <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                                <Film size={16} className="text-indigo-400" />
                                Transcode Approval Queue
                                {pendingCount > 0 && (
                                    <span className="bg-amber-500/20 text-amber-400 text-[10px] font-bold px-2 py-0.5 rounded-full border border-amber-500/30">
                                        {pendingCount} Pending
                                    </span>
                                )}
                            </h3>
                            <span className="text-xs text-slate-500">{queueList.length} total items</span>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 uppercase tracking-wider text-[11px]">
                                        <th className="py-2.5 px-3 font-semibold">File</th>
                                        <th className="py-2.5 px-3 font-semibold">Size</th>
                                        <th className="py-2.5 px-3 font-semibold">Codec Transition</th>
                                        <th className="py-2.5 px-3 font-semibold">Status</th>
                                        <th className="py-2.5 px-3 font-semibold text-right">Action</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/[0.04]">
                                    {error ? (
                                        <tr><td colSpan={5} className="py-12 text-center text-red-400">Failed to load transcode queue</td></tr>
                                    ) : isLoading || !queue ? (
                                        <tr><td colSpan={5} className="py-12 text-center text-slate-500">
                                            <div className="flex items-center justify-center gap-2">
                                                <Loader2 size={16} className="animate-spin text-indigo-400" />
                                                <span>Loading queue...</span>
                                            </div>
                                        </td></tr>
                                    ) : queueList.length === 0 ? (
                                        <tr><td colSpan={5} className="py-12 text-center text-slate-500">No media queued. Run a scan against /home/hdd to index videos.</td></tr>
                                    ) : (
                                        queueList.map(item => (
                                            <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3">
                                                    <p className="font-medium text-slate-200 truncate max-w-xs md:max-w-md" title={item.filePath}>
                                                        {item.filePath.split(/[/\\]/).pop()}
                                                    </p>
                                                    <p className="text-[10px] text-slate-500 truncate max-w-xs md:max-w-md mt-0.5">{item.filePath}</p>
                                                </td>
                                                <td className="py-3 px-3 text-slate-400 font-mono">
                                                    {formatBytes(item.originalSize)}
                                                </td>
                                                <td className="py-3 px-3">
                                                    <span className="bg-white/10 text-slate-300 text-[10px] px-2 py-0.5 rounded font-mono border border-white/5">{item.originalCodec}</span>
                                                    {item.newCodec && (
                                                        <span className="ml-1.5 bg-indigo-500/20 text-indigo-300 text-[10px] px-2 py-0.5 rounded font-mono border border-indigo-500/20">&rarr; {item.newCodec}</span>
                                                    )}
                                                </td>
                                                <td className="py-3 px-3">
                                                    {item.status === 'PENDING_APPROVAL' && (
                                                        <span className="text-amber-400 text-xs flex items-center gap-1 font-semibold">
                                                            <ArrowRightCircle size={13} /> Needs Approval
                                                        </span>
                                                    )}
                                                    {item.status === 'APPROVED' && (
                                                        <span className="text-blue-400 text-xs flex items-center gap-1">
                                                            <Loader2 size={13} className="animate-spin" /> Queued
                                                        </span>
                                                    )}
                                                    {item.status === 'PROCESSING' && (
                                                        <span className="text-indigo-400 text-xs font-bold flex items-center gap-1">
                                                            <Loader2 size={13} className="animate-spin" /> Processing
                                                        </span>
                                                    )}
                                                    {item.status === 'COMPLETED' && (
                                                        <span className="text-emerald-400 text-xs flex items-center gap-1 font-semibold">
                                                            <CheckCircle size={13} /> Saved {formatBytes(item.originalSize - item.newSize)}
                                                        </span>
                                                    )}
                                                    {item.status === 'FAILED' && (
                                                        <span className="text-red-400 text-xs flex items-center gap-1">
                                                            <XCircle size={13} /> Failed
                                                        </span>
                                                    )}
                                                </td>
                                                <td className="py-3 px-3 text-right">
                                                    {item.status === 'PENDING_APPROVAL' && (
                                                        <button
                                                            onClick={() => handleApprove(item.id)}
                                                            className="obs-touch-target-standard obs-gpu-120hz-interactive bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 px-3 py-1 rounded-lg text-xs font-bold transition-all inline-flex items-center gap-1.5"
                                                        >
                                                            <Play size={12} />
                                                            <span>Authorize</span>
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
