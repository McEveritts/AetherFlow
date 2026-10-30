import { useState, useEffect, useRef } from 'react';
import { Sparkles, FolderSearch, Film, Music, Subtitles, Loader2, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import PathSelector from '@/components/ui/PathSelector';

interface EnrichedMedia {
    id: number;
    file_path: string;
    filename: string;
    title: string;
    year: string;
    language: string;
    quality: string;
    subtitles_json: string;
    enriched_at: string;
}

interface ScanStatus {
    scanning: boolean;
    progress: number;
    total: number;
    done: number;
    error: string;
}

export default function MetadataTab() {
    const [scanPath, setScanPath] = useState('/home/hdd');
    const [status, setStatus] = useState<ScanStatus | null>(null);
    const [results, setResults] = useState<EnrichedMedia[]>([]);
    const [isLoadingResults, setIsLoadingResults] = useState(false);
    const pollTimerRef = useRef<NodeJS.Timeout | null>(null);

    const fetchResults = async () => {
        setIsLoadingResults(true);
        try {
            const res = await apiFetch('/api/v1/admin/ai/metadata/results');
            if (res.ok) {
                const data = await res.json();
                setResults(Array.isArray(data) ? data : []);
            }
        } catch (err) {
            console.error('Failed to fetch enriched metadata results', err);
        } finally {
            setIsLoadingResults(false);
        }
    };

    // Load existing metadata on mount
    useEffect(() => {
        fetchResults();
        return () => {
            if (pollTimerRef.current) {
                clearInterval(pollTimerRef.current);
            }
        };
    }, []);

    const startScan = async () => {
        if (!scanPath.trim() || status?.scanning) return;

        setStatus({ scanning: true, progress: 0, total: 0, done: 0, error: '' });

        try {
            const res = await apiFetch('/api/v1/admin/ai/metadata/scan', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ path: scanPath.trim() })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || `Failed to initiate metadata scan: ${res.status}`);
            }

            // Start polling GET /api/v1/admin/ai/metadata/status every 1.5s
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);

            pollTimerRef.current = setInterval(async () => {
                try {
                    const statusRes = await apiFetch('/api/v1/admin/ai/metadata/status');
                    if (statusRes.ok) {
                        const statusData: ScanStatus = await statusRes.json();
                        setStatus(statusData);

                        if (!statusData.scanning) {
                            if (pollTimerRef.current) {
                                clearInterval(pollTimerRef.current);
                                pollTimerRef.current = null;
                            }
                            fetchResults();
                        }
                    }
                } catch (pollErr) {
                    console.error("Metadata status polling error", pollErr);
                }
            }, 1500);

        } catch (err) {
            setStatus({
                scanning: false,
                progress: 0,
                total: 0,
                done: 0,
                error: err instanceof Error ? err.message : 'Metadata scan request failed'
            });
        }
    };

    const getFileIcon = (filename: string) => {
        const ext = filename.split('.').pop()?.toLowerCase();
        if (['srt', 'ass', 'ssa', 'sub', 'vtt'].includes(ext || '')) return <Subtitles size={15} className="text-cyan-400" />;
        if (['mp3', 'flac', 'aac', 'ogg', 'opus'].includes(ext || '')) return <Music size={15} className="text-purple-400" />;
        return <Film size={15} className="text-blue-400" />;
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Scan Controls Card */}
            <div className="relative z-20 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                    <div className="flex items-center gap-3">
                        <div className="h-10 w-10 bg-violet-500/20 rounded-xl flex items-center justify-center border border-violet-500/30 text-violet-400 shrink-0">
                            <Sparkles size={20} />
                        </div>
                        <div>
                            <h2 className="text-base font-bold text-slate-100">AI Media Metadata Enrichment</h2>
                            <p className="text-xs text-slate-400 mt-0.5">Powered by Gemini 4 Argon — Scans directories, identifies titles, languages, and subtitle matches</p>
                        </div>
                    </div>
                </div>

                <div className="flex flex-col md:flex-row gap-2.5 items-stretch md:items-center">
                    <PathSelector
                        value={scanPath}
                        onChange={setScanPath}
                        placeholder="/home/hdd"
                        className="flex-1 text-xs"
                    />
                    <button
                        onClick={startScan}
                        disabled={!scanPath.trim() || status?.scanning}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:bg-violet-600/40 disabled:cursor-not-allowed text-white text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-violet-500/20 shrink-0"
                    >
                        {status?.scanning ? (
                            <><Loader2 size={15} className="animate-spin" /> Scanning...</>
                        ) : (
                            <><FolderSearch size={15} /> Scan &amp; Enrich</>
                        )}
                    </button>
                </div>

                {/* Progress Bar */}
                {status?.scanning && (
                    <div className="mt-4 pt-3 border-t border-white/[0.06]">
                        <div className="flex justify-between text-xs text-slate-400 mb-1.5">
                            <span className="flex items-center gap-1.5">
                                <Loader2 size={13} className="animate-spin text-violet-400" />
                                Processing {status.done} / {status.total} files
                            </span>
                            <span className="font-mono text-violet-300 font-semibold">{status.progress.toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-violet-500 to-indigo-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.max(status.progress, 3)}%` }}
                            />
                        </div>
                    </div>
                )}

                {/* Error Display */}
                {status?.error && !status.scanning && (
                    <div className="mt-3.5 p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-2 text-xs text-red-300">
                        <AlertCircle size={15} className="text-red-400 shrink-0" />
                        <span>{status.error}</span>
                    </div>
                )}

                {/* Success Display */}
                {status && !status.scanning && !status.error && status.done > 0 && (
                    <div className="mt-3.5 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center gap-2 text-xs text-emerald-300">
                        <CheckCircle2 size={15} className="text-emerald-400 shrink-0" />
                        <span>Enrichment complete &mdash; {status.done} files processed by Gemini 4 Argon</span>
                    </div>
                )}
            </div>

            {/* Results Table */}
            <div className="relative z-10 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2">
                        <Film size={16} className="text-violet-400" />
                        <h3 className="text-sm font-bold text-slate-200">Enriched Media Library</h3>
                        <span className="text-xs text-slate-500">({results.length} records)</span>
                    </div>
                    <button
                        onClick={fetchResults}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive text-xs text-violet-300 hover:text-white bg-violet-500/10 hover:bg-violet-500/20 px-3 py-1.5 rounded-xl border border-violet-500/20 transition-all flex items-center gap-1.5"
                    >
                        <RefreshCw size={13} className={isLoadingResults ? 'animate-spin' : ''} />
                        <span>Refresh</span>
                    </button>
                </div>

                {isLoadingResults && results.length === 0 ? (
                    <div className="text-center py-16">
                        <Loader2 size={28} className="animate-spin mx-auto text-violet-400 mb-2" />
                        <p className="text-slate-400 text-xs">Loading enriched metadata...</p>
                    </div>
                ) : results.length === 0 ? (
                    <div className="text-center py-16">
                        <FolderSearch size={40} className="mx-auto text-slate-600 mb-3" />
                        <p className="text-slate-300 text-sm font-semibold">No enriched metadata yet</p>
                        <p className="text-slate-500 text-xs mt-1">Scan a media directory (/home/hdd) to enrich titles, language, and subtitle details.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left border-collapse">
                            <thead>
                                <tr className="border-b border-white/[0.06] text-slate-400 uppercase tracking-wider text-[11px]">
                                    <th className="py-2.5 px-3 font-semibold">File</th>
                                    <th className="py-2.5 px-3 font-semibold">Title</th>
                                    <th className="py-2.5 px-3 font-semibold">Year</th>
                                    <th className="py-2.5 px-3 font-semibold">Language</th>
                                    <th className="py-2.5 px-3 font-semibold">Quality</th>
                                    <th className="py-2.5 px-3 font-semibold">Subtitles</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04]">
                                {results.map((item) => {
                                    let subtitles: string[] = [];
                                    try { subtitles = JSON.parse(item.subtitles_json || '[]'); } catch { /* ignore */ }
                                    return (
                                        <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                                            <td className="py-3 px-3">
                                                <div className="flex items-center gap-2">
                                                    {getFileIcon(item.filename)}
                                                    <span className="text-slate-300 font-mono text-xs truncate max-w-[220px]" title={item.filename}>
                                                        {item.filename}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="py-3 px-3 text-slate-200 font-medium">{item.title || '—'}</td>
                                            <td className="py-3 px-3 text-slate-400">{item.year || '—'}</td>
                                            <td className="py-3 px-3">
                                                <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded-md text-[11px] border border-blue-500/20 font-medium">
                                                    {item.language || 'unknown'}
                                                </span>
                                            </td>
                                            <td className="py-3 px-3">
                                                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded-md text-[11px] border border-emerald-500/20 font-medium">
                                                    {item.quality || 'unknown'}
                                                </span>
                                            </td>
                                            <td className="py-3 px-3">
                                                <div className="flex gap-1 flex-wrap">
                                                    {subtitles.length > 0 ? subtitles.map((sub, i) => (
                                                        <span key={i} className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-[10px] border border-cyan-500/20">
                                                            {sub}
                                                        </span>
                                                    )) : <span className="text-slate-600">—</span>}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
