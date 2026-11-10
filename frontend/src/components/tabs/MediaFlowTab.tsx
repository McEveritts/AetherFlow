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

    const handleDecline = async (id: number) => {
        try {
            await apiFetch(`/api/v1/admin/mediaflow/decline/${id}`, {
                method: 'POST'
            });
            mutate();
            addToast('Transcode job declined.', 'info');
        } catch {
            addToast('Failed to decline transcode job.', 'error');
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
    const pendingCount = queueList.filter((queueEntry) => queueEntry.status === 'PENDING_APPROVAL').length;
    const completedCount = queueList.filter((queueEntry) => queueEntry.status === 'COMPLETED').length;
    const totalSavedBytes = queueList
        .filter((queueEntry) => queueEntry.status === 'COMPLETED' && queueEntry.originalSize > queueEntry.newSize)
        .reduce((accumulatedBytes, queueEntry) => accumulatedBytes + (queueEntry.originalSize - queueEntry.newSize), 0);

    return (
        <div className="animate-fade-in relative z-10 w-full min-w-0 max-w-full">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.07] relative z-30 shrink-0">
                <div className="flex items-center gap-3 min-w-0">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/15 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400 shrink-0">
                        {activeSection === 'transcode' ? <Film size={20} /> : <Sparkles size={20} />}
                    </div>
                    <div className="min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                            <h2 className="text-base sm:text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">MediaFlow Engine</h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Hardware Accelerated
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5 shrink-0">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400 animate-pulse"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide truncate">
                                VAAPI / AMF &middot; Live Transcode & AI Metadata
                            </span>
                        </div>
                    </div>
                </div>

                {/* Section Switcher & Controls */}
                <div className="flex flex-wrap items-center gap-2">
                    <div className="flex items-center gap-1 p-1 bg-white/[0.03] border border-white/[0.08] rounded-xl" role="group" aria-label="MediaFlow view section">
                        <button
                            type="button"
                            onClick={() => setActiveSection('transcode')}
                            aria-label="Switch to Transcode Queue view"
                            aria-pressed={activeSection === 'transcode'}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                activeSection === 'transcode'
                                    ? 'bg-indigo-600/30 border border-indigo-500/50 text-indigo-200 shadow-sm'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Film size={14} />
                            <span>Transcode Queue</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveSection('metadata')}
                            aria-label="Switch to Metadata Enrichment view"
                            aria-pressed={activeSection === 'metadata'}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-violet-500 focus-visible:outline-none ${
                                activeSection === 'metadata'
                                    ? 'bg-violet-600/30 border border-violet-500/50 text-violet-200 shadow-sm'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Sparkles size={14} />
                            <span>Metadata Enrichment</span>
                        </button>
                    </div>

                    {activeSection === 'transcode' && (
                        <button
                            type="button"
                            onClick={() => mutate()}
                            aria-label="Refresh transcode queue"
                            className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none"
                            title="Refresh Queue"
                        >
                            <RefreshCw size={14} className={isValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                            <span>Refresh</span>
                        </button>
                    )}
                </div>
            </div>

            {activeSection === 'metadata' ? (
                <div className="p-5">
                    <MetadataTab />
                </div>
            ) : (
                <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 min-w-0 border-b border-white/[0.07]">
                        <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                            <div className="min-w-0 flex-1">
                                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                    Pending Approvals
                                </span>
                                <div className="text-xl sm:text-2xl font-bold font-mono text-amber-400 mt-1 break-words">
                                    {pendingCount}
                                </div>
                                <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                    Awaiting operator signoff
                                </span>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0 ml-3">
                                <ArrowRightCircle size={18} />
                            </div>
                        </div>

                        <div className="p-4 sm:p-5 flex items-center justify-between min-w-0 border-t sm:border-t-0 sm:border-l border-white/[0.07]">
                            <div className="min-w-0 flex-1">
                                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                    Completed Jobs
                                </span>
                                <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1 break-words">
                                    {completedCount}
                                </div>
                                <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                    Transcoded & verified
                                </span>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0 ml-3">
                                <CheckCircle size={18} />
                            </div>
                        </div>

                        <div className="p-4 sm:p-5 flex items-center justify-between min-w-0 border-t xl:border-t-0 xl:border-l border-white/[0.07]">
                            <div className="min-w-0 flex-1">
                                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                    Space Saved
                                </span>
                                <div className="text-xl sm:text-2xl font-bold font-mono text-cyan-300 mt-1 break-words">
                                    {formatBytes(totalSavedBytes)}
                                </div>
                                <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                    Compression reduction
                                </span>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0 ml-3">
                                <HardDrive size={18} />
                            </div>
                        </div>

                        <div className="p-4 sm:p-5 flex items-center justify-between min-w-0 border-t sm:border-l xl:border-t-0 border-white/[0.07]">
                            <div className="min-w-0 flex-1">
                                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                                    Hardware Engine
                                </span>
                                <div className="text-base sm:text-lg font-bold font-mono text-fuchsia-300 mt-1 break-words">
                                    {progress && progress.status === 'PROCESSING' ? `${progress.speed}x Active` : 'VAAPI / AMF Standby'}
                                </div>
                                <span className="text-xs text-slate-500 mt-0.5 block break-words">
                                    AMD / Intel Native GPU
                                </span>
                            </div>
                            <div className="h-10 w-10 rounded-xl bg-fuchsia-500/10 border border-fuchsia-500/20 flex items-center justify-center text-fuchsia-400 shrink-0 ml-3">
                                <Zap size={18} />
                            </div>
                        </div>
                    </div>

                    <div className="border-b border-white/[0.07] px-5 py-3.5 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-white/[0.005]">
                        <div className="flex items-center gap-3 min-w-0">
                            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                                <HardDrive size={16} />
                            </div>
                            <div className="min-w-0">
                                <h3 className="text-xs font-bold text-slate-200">Library Scanner</h3>
                                <p className="text-xs text-slate-400 break-words">Scan filesystem to queue videos with legacy codecs for transcode optimization</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                            <PathSelector
                                value={scanDir}
                                onChange={setScanDir}
                                placeholder="/home/hdd"
                                className="w-full md:w-72 text-xs"
                            />
                            <button
                                type="button"
                                onClick={triggerScan}
                                disabled={isScanning}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[40px] px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-all shadow-sm flex items-center justify-center gap-1.5 shrink-0 disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none"
                            >
                                {isScanning ? <Loader2 size={13} className="animate-spin" /> : <HardDrive size={13} />}
                                <span>Scan Library</span>
                            </button>
                        </div>
                    </div>

                    {progress && progress.status === 'PROCESSING' && (
                        <div className="border-b border-indigo-500/30 bg-indigo-950/[0.15] p-5 relative z-10 overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-black/50">
                                <div className="h-full bg-indigo-500 animate-pulse w-full"></div>
                            </div>
                            <div className="flex justify-between items-center mb-3">
                                <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                                    <Loader2 className="animate-spin text-indigo-400" size={18} />
                                    Active Hardware Transcode
                                </h3>
                                <span className="bg-indigo-500/20 text-indigo-300 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold tracking-wider border border-indigo-500/30">
                                    VAAPI/AMF ACTIVE
                                </span>
                            </div>
                            <p className="text-indigo-200 text-xs sm:text-sm font-medium mb-4 break-words [overflow-wrap:anywhere]" title={progress.filePath}>{progress.filePath}</p>

                            <div className="obs-metric-strip">
                                <div className="p-3">
                                    <span className="text-slate-400 text-xs font-bold uppercase tracking-wider block mb-0.5">FPS</span>
                                    <span className="text-lg sm:text-xl font-mono text-white">{progress.fps}</span>
                                </div>
                                <div className="p-3">
                                    <span className="text-slate-400 text-xs font-bold uppercase tracking-wider block mb-0.5">Speed</span>
                                    <span className="text-lg sm:text-xl font-mono text-amber-400">{progress.speed}x</span>
                                </div>
                                <div className="p-3">
                                    <span className="text-slate-400 text-xs font-bold uppercase tracking-wider block mb-0.5">Elapsed</span>
                                    <span className="text-lg sm:text-xl font-mono text-white">{progress.time}</span>
                                </div>
                                <div className="p-3">
                                    <span className="text-slate-400 text-xs font-bold uppercase tracking-wider block mb-0.5">Size</span>
                                    <span className="text-lg sm:text-xl font-mono text-white">{progress.size}</span>
                                </div>
                            </div>
                        </div>
                    )}

                    <section aria-label="Transcode approval queue" className="min-w-0">
                        <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.07] bg-white/[0.005]">
                            <h3 className="text-xs sm:text-sm font-bold text-slate-200 flex items-center gap-2">
                                <Film size={15} className="text-indigo-400" />
                                <span>Transcode Approval Queue</span>
                                {pendingCount > 0 && (
                                    <span className="bg-amber-500/20 text-amber-300 text-xs font-bold px-2 py-0.5 rounded-full border border-amber-500/30">
                                        {pendingCount} Pending
                                    </span>
                                )}
                            </h3>
                            <span className="text-xs text-slate-400">{queueList.length} total items</span>
                        </div>

                        <div className="overflow-x-auto min-w-0 max-w-full">
                            <table className="w-full text-left border-collapse text-xs border-b border-white/[0.07] block xl:table xl:table-fixed">
                                <thead className="hidden xl:table-header-group">
                                    <tr className="border-b border-white/[0.07] text-slate-400 uppercase tracking-wider text-xs bg-white/[0.01]">
                                        <th id="queue-header-file" scope="col" className="py-3 px-5 font-semibold w-[24%]">File</th>
                                        <th id="queue-header-size" scope="col" className="py-3 px-5 font-semibold w-[12%]">Size</th>
                                        <th id="queue-header-codec" scope="col" className="py-3 px-5 font-semibold w-[28%]">Codec Transition</th>
                                        <th id="queue-header-status" scope="col" className="py-3 px-5 font-semibold w-[14%]">Status</th>
                                        <th id="queue-header-action" scope="col" className="py-3 px-5 font-semibold text-right w-[22%]">Action</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/[0.06] block xl:table-row-group">
                                    {error ? (
                                        <tr className="block xl:table-row"><td colSpan={5} className="py-12 text-center text-rose-300 block xl:table-cell">Failed to load transcode queue</td></tr>
                                    ) : isLoading || !queue ? (
                                        <tr className="block xl:table-row"><td colSpan={5} className="py-12 text-center text-slate-400 block xl:table-cell">
                                            <div className="flex items-center justify-center gap-2">
                                                <Loader2 size={16} className="animate-spin text-indigo-400" />
                                                <span>Loading queue...</span>
                                            </div>
                                        </td></tr>
                                    ) : queueList.length === 0 ? (
                                        <tr className="block xl:table-row"><td colSpan={5} className="py-12 text-center text-slate-400 block xl:table-cell">No media queued. Run a scan against /home/hdd to index videos.</td></tr>
                                    ) : (
                                        queueList.map((queueItem) => (
                                            <tr key={queueItem.id} className="block xl:table-row hover:bg-white/[0.02] transition-colors p-4 sm:p-5 xl:p-0 border-b border-white/[0.06] xl:border-b-0">
                                                <td headers="queue-header-file" className="block xl:table-cell py-0 xl:py-3.5 px-0 xl:px-5 min-w-0">
                                                    <p className="font-semibold text-slate-200 truncate" title={queueItem.filePath}>
                                                        {queueItem.filePath.split(/[/\\\\]/).pop()}
                                                    </p>
                                                    <p className="text-xs text-slate-400 break-words [overflow-wrap:anywhere] mt-0.5" title={queueItem.filePath}>{queueItem.filePath}</p>
                                                </td>
                                                <td headers="queue-header-size" className="inline-block xl:table-cell py-0 xl:py-3.5 px-0 xl:px-5 text-slate-300 font-mono whitespace-nowrap mt-2 xl:mt-0 mr-4 xl:mr-0 text-xs">
                                                    <span className="xl:hidden text-slate-400 font-sans mr-1.5 uppercase font-medium text-xs">Size:</span>
                                                    {formatBytes(queueItem.originalSize)}
                                                </td>
                                                <td headers="queue-header-codec" className="block xl:table-cell py-0 xl:py-3.5 px-0 xl:px-5 leading-relaxed mt-2 xl:mt-0 text-xs min-w-0">
                                                    <span className="xl:hidden text-slate-400 mr-1.5 uppercase font-medium text-xs">Codec:</span>
                                                    <div className="flex flex-col items-start gap-1.5 min-w-0">
                                                        <span className="block max-w-full break-words bg-white/10 text-slate-300 text-xs px-2 py-1 rounded font-mono border border-white/5">{queueItem.originalCodec}</span>
                                                        {queueItem.newCodec && (
                                                            <span className="block max-w-full break-words bg-indigo-500/20 text-indigo-300 text-xs px-2 py-1 rounded font-mono border border-indigo-500/20">&rarr; {queueItem.newCodec}</span>
                                                        )}
                                                    </div>
                                                </td>
                                                <td headers="queue-header-status" className="inline-block xl:table-cell py-0 xl:py-3.5 px-0 xl:px-5 mt-2 xl:mt-0 text-xs">
                                                    <span className="xl:hidden text-slate-400 mr-1.5 uppercase font-medium text-xs">Status:</span>
                                                    {queueItem.status === 'PENDING_APPROVAL' && (
                                                        <span className="text-amber-400 text-xs inline-flex items-center gap-1 font-semibold">
                                                            <ArrowRightCircle size={13} /> Needs Approval
                                                        </span>
                                                    )}
                                                    {queueItem.status === 'APPROVED' && (
                                                        <span className="text-cyan-400 text-xs inline-flex items-center gap-1">
                                                            <Loader2 size={13} className="animate-spin" /> Queued
                                                        </span>
                                                    )}
                                                    {queueItem.status === 'PROCESSING' && (
                                                        <span className="text-indigo-400 text-xs font-bold inline-flex items-center gap-1">
                                                            <Loader2 size={13} className="animate-spin" /> Processing
                                                        </span>
                                                    )}
                                                    {queueItem.status === 'COMPLETED' && (
                                                        <span className="text-emerald-400 text-xs inline-flex items-center gap-1 font-semibold">
                                                            <CheckCircle size={13} /> Saved {formatBytes(queueItem.originalSize - queueItem.newSize)}
                                                        </span>
                                                    )}
                                                    {queueItem.status === 'FAILED' && (
                                                        <span className="text-rose-400 text-xs inline-flex items-center gap-1">
                                                            <XCircle size={13} /> Failed
                                                        </span>
                                                    )}
                                                </td>
                                                <td headers="queue-header-action" className={`block xl:table-cell py-0 xl:py-3.5 px-0 xl:px-5 text-left xl:text-right ${queueItem.status === 'PENDING_APPROVAL' ? 'mt-3 xl:mt-0 pt-2 xl:pt-3.5 border-t border-white/[0.04] xl:border-t-0' : 'empty:hidden'}`}>
                                                    {queueItem.status === 'PENDING_APPROVAL' && (
                                                        <div className="flex flex-wrap items-center justify-start xl:justify-end gap-2">
                                                            <button
                                                                type="button"
                                                                onClick={() => handleApprove(queueItem.id)}
                                                                aria-label={`Authorize transcode for ${queueItem.filePath.split(/[/\\\\]/).pop()}`}
                                                                className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[44px] bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all inline-flex items-center gap-1.5"
                                                            >
                                                                <Play size={12} />
                                                                <span>Authorize</span>
                                                            </button>
                                                            <button
                                                                type="button"
                                                                onClick={() => handleDecline(queueItem.id)}
                                                                aria-label={`Decline transcode for ${queueItem.filePath.split(/[/\\\\]/).pop()}`}
                                                                className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[44px] bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all inline-flex items-center gap-1.5"
                                                            >
                                                                <XCircle size={12} />
                                                                <span>Decline</span>
                                                            </button>
                                                        </div>
                                                    )}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </section>
                </>
            )}
        </div>
    );
}
