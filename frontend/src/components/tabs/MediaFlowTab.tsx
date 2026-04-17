import React, { useState, useEffect } from 'react';
import useSWR from 'swr';
import { Film, Play, CheckCircle, XCircle, Loader2, ArrowRightCircle, HardDrive } from 'lucide-react';
import { Card } from '@/components/ui/Card';

const fetcher = (url: string) => fetch(url, {
    headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
}).then(res => res.json());

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
        const token = localStorage.getItem('token');
        if (!token) return;

        const eventSource = new EventSource(`/api/v1/deploy/stream?appName=mediaflow_engine`);
        
        eventSource.onmessage = (event) => {
            try {
                const data: StreamProgress = JSON.parse(event.data);
                setProgress(data);
            } catch (err) {
                console.error("SSE parse error", err);
            }
        };

        return () => {
            eventSource.close();
        };
    }, []);

    return progress;
}

const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function MediaFlowTab() {
    const { data: queue, mutate } = useSWR<QueueItem[]>('/api/v1/admin/mediaflow/queue', fetcher);
    const progress = useMediaFlowStream();
    const [scanDir, setScanDir] = useState('/mnt/media/movies');

    const handleApprove = async (id: number) => {
        await fetch(`/api/v1/admin/mediaflow/approve/${id}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        mutate();
    };

    const triggerScan = async () => {
        await fetch('/api/v1/admin/mediaflow/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ directory: scanDir })
        });
        alert('Background scan initiated across ' + scanDir);
    };

    const pendingCount = queue?.filter(i => i.status === 'PENDING_APPROVAL').length || 0;

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 max-w-7xl mx-auto">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-400 to-indigo-500 drop-shadow-sm flex items-center gap-3">
                        <Film className="text-indigo-400" size={32} />
                        MediaFlow Engine
                    </h2>
                    <p className="text-slate-400 text-sm mt-1 max-w-2xl">
                        Passive bare-metal video transcoder. Aggressively compresses legacy formats using AMD native hardware acceleration. Requires explicit user approval per file.
                    </p>
                </div>
                
                <div className="flex gap-2 w-full md:w-auto">
                    <input 
                        type="text" 
                        value={scanDir}
                        onChange={(e) => setScanDir(e.target.value)}
                        className="bg-black/50 border border-white/10 rounded-lg px-4 py-2 text-sm text-zinc-300 w-full md:w-64 focus:outline-none focus:border-indigo-500/50"
                    />
                    <button 
                        onClick={triggerScan}
                        className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-600 text-white px-4 py-2 rounded-lg font-medium shadow-lg transition-colors whitespace-nowrap"
                    >
                        <HardDrive size={16} />
                        Scan Library
                    </button>
                </div>
            </div>

            {/* Active Transcode Section */}
            {(progress && progress.status === 'PROCESSING') && (
                <Card className="bg-gradient-to-tr from-indigo-900/30 to-black/40 border-indigo-500/30 overflow-hidden relative">
                    <div className="absolute top-0 left-0 w-full h-1 bg-black/50">
                        {/* Fake pulsing bar as native ffmpeg doesn't emit pure % without duration knowledge, but we simulate activity */}
                        <div className="h-full bg-indigo-500 animate-pulse w-full"></div>
                    </div>
                    <div className="p-6">
                        <div className="flex justify-between items-center mb-4">
                            <h3 className="text-xl font-bold text-white flex items-center gap-3">
                                <Loader2 className="animate-spin text-indigo-400" size={24} />
                                Active Hardware Transcode
                            </h3>
                            <div className="bg-indigo-500/20 text-indigo-300 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider border border-indigo-500/30">
                                VAAPI/AMF ACTIVE
                            </div>
                        </div>
                        
                        <p className="text-indigo-200 font-medium text-lg mb-6 truncate" title={progress.filePath}>{progress.filePath}</p>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="bg-black/40 rounded-lg p-4 border border-white/5">
                                <span className="text-zinc-500 text-xs font-bold uppercase tracking-wider block mb-1">FPS</span>
                                <span className="text-2xl font-mono text-white">{progress.fps}</span>
                            </div>
                            <div className="bg-black/40 rounded-lg p-4 border border-white/5">
                                <span className="text-zinc-500 text-xs font-bold uppercase tracking-wider block mb-1">Speed</span>
                                <span className="text-2xl font-mono text-amber-400">{progress.speed}x</span>
                            </div>
                            <div className="bg-black/40 rounded-lg p-4 border border-white/5">
                                <span className="text-zinc-500 text-xs font-bold uppercase tracking-wider block mb-1">Time Elapsed</span>
                                <span className="text-2xl font-mono text-white">{progress.time}</span>
                            </div>
                            <div className="bg-black/40 rounded-lg p-4 border border-white/5">
                                <span className="text-zinc-500 text-xs font-bold uppercase tracking-wider block mb-1">Current Size</span>
                                <span className="text-2xl font-mono text-white">{progress.size}</span>
                            </div>
                        </div>
                    </div>
                </Card>
            )}

            {/* Approval Inbox */}
            <Card className="overflow-hidden">
                <div className="p-4 border-b border-white/5 flex justify-between items-center bg-black/20">
                    <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                        Approval Inbox
                        <span className="bg-amber-500/20 text-amber-500 text-xs px-2 py-0.5 rounded-full">{pendingCount}</span>
                    </h3>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-black/40 text-zinc-500 text-xs uppercase tracking-widest border-b border-white/5">
                                <th className="p-4 font-semibold">File</th>
                                <th className="p-4 font-semibold">Size</th>
                                <th className="p-4 font-semibold">Codec</th>
                                <th className="p-4 font-semibold">Status</th>
                                <th className="p-4 font-semibold text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {!queue ? (
                                <tr><td colSpan={5} className="p-8 text-center text-zinc-500">Loading queue...</td></tr>
                            ) : queue.length === 0 ? (
                                <tr><td colSpan={5} className="p-8 text-center text-zinc-500">No media queued. Run a scan.</td></tr>
                            ) : (
                                queue.map(item => (
                                    <tr key={item.id} className="hover:bg-white/[0.02] transition-colors group">
                                        <td className="p-4">
                                            <p className="text-sm font-medium text-slate-300 truncate max-w-sm md:max-w-md" title={item.filePath}>
                                                {item.filePath.split(/[/\\]/).pop()}
                                            </p>
                                        </td>
                                        <td className="p-4 text-sm text-zinc-400 font-mono">
                                            {formatBytes(item.originalSize)}
                                        </td>
                                        <td className="p-4">
                                            <span className="bg-white/10 text-zinc-300 text-xs px-2 py-1 rounded font-mono border border-white/5">{item.originalCodec}</span>
                                            {item.newCodec && (
                                                <span className="ml-2 bg-indigo-500/20 text-indigo-300 text-xs px-2 py-1 rounded font-mono border border-indigo-500/20">-> {item.newCodec}</span>
                                            )}
                                        </td>
                                        <td className="p-4">
                                            {item.status === 'PENDING_APPROVAL' && <span className="text-amber-500 text-sm flex items-center gap-1"><ArrowRightCircle size={14}/> Needs Approval</span>}
                                            {item.status === 'APPROVED' && <span className="text-blue-400 text-sm flex items-center gap-1"><Loader2 size={14} className="animate-spin"/> Queued</span>}
                                            {item.status === 'PROCESSING' && <span className="text-indigo-400 text-sm font-bold flex items-center gap-1"><Loader2 size={14} className="animate-spin"/> Processing</span>}
                                            {item.status === 'COMPLETED' && <span className="text-emerald-500 text-sm flex items-center gap-1"><CheckCircle size={14}/> Saved {formatBytes(item.originalSize - item.newSize)}</span>}
                                            {item.status === 'FAILED' && <span className="text-red-500 text-sm flex items-center gap-1"><XCircle size={14}/> Failed</span>}
                                        </td>
                                        <td className="p-4 text-right">
                                            {item.status === 'PENDING_APPROVAL' && (
                                                <button 
                                                    onClick={() => handleApprove(item.id)}
                                                    className="bg-zinc-800 hover:bg-emerald-600 border border-zinc-700 hover:border-emerald-500 text-zinc-300 hover:text-white px-3 py-1.5 rounded text-sm font-medium transition-all flex items-center gap-2 ml-auto"
                                                >
                                                    <Play size={14} /> Process
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
}
