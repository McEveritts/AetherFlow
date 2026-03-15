import { Sparkles, FolderSearch, Film, Music, Subtitles, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import { useState } from 'react';

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
    const [scanPath, setScanPath] = useState('');
    const [status, setStatus] = useState<ScanStatus | null>(null);
    const [results, setResults] = useState<EnrichedMedia[]>([]);
    const [isLoadingResults, setIsLoadingResults] = useState(false);

    const startScan = async () => {
        if (!scanPath.trim()) return;

        try {
            const res = await fetch('/api/ai/metadata/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: scanPath.trim() })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);

            // Start polling status
            pollStatus();
        } catch (err) {
            setStatus({ scanning: false, progress: 0, total: 0, done: 0, error: err instanceof Error ? err.message : 'Scan failed' });
        }
    };

    const pollStatus = () => {
        const interval = setInterval(async () => {
            try {
                const res = await fetch('/api/ai/metadata/status');
                const data: ScanStatus = await res.json();
                setStatus(data);

                if (!data.scanning) {
                    clearInterval(interval);
                    fetchResults();
                }
            } catch {
                clearInterval(interval);
            }
        }, 2000);
    };

    const fetchResults = async () => {
        setIsLoadingResults(true);
        try {
            const res = await fetch('/api/ai/metadata/results');
            const data = await res.json();
            setResults(data);
        } catch {
            console.error('Failed to fetch results');
        } finally {
            setIsLoadingResults(false);
        }
    };

    const getFileIcon = (filename: string) => {
        const ext = filename.split('.').pop()?.toLowerCase();
        if (['srt', 'ass', 'ssa', 'sub', 'vtt'].includes(ext || '')) return <Subtitles size={16} className="text-cyan-400" />;
        if (['mp3', 'flac', 'aac', 'ogg', 'opus'].includes(ext || '')) return <Music size={16} className="text-purple-400" />;
        return <Film size={16} className="text-blue-400" />;
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-[calc(100vh-10rem)]">

            {/* Header Card — Scan Input */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-8 backdrop-blur-xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-[400px] h-[400px] bg-violet-500/10 rounded-full blur-[100px] pointer-events-none -translate-x-1/2 -translate-y-1/2"></div>

                <div className="flex items-center gap-4 mb-6 relative z-10">
                    <div className="h-12 w-12 bg-violet-500/20 rounded-2xl flex items-center justify-center border border-violet-500/30">
                        <Sparkles size={24} className="text-violet-400" />
                    </div>
                    <div>
                        <h2 className="text-xl font-bold text-slate-100">AI Media Metadata Enrichment</h2>
                        <p className="text-sm text-slate-400 mt-0.5">Powered by Gemini — Scans directories, identifies titles, languages, and subtitle matches</p>
                    </div>
                </div>

                <div className="flex gap-3 relative z-10">
                    <input
                        type="text"
                        value={scanPath}
                        onChange={(e) => setScanPath(e.target.value)}
                        placeholder="/path/to/media/directory"
                        className="flex-1 bg-white/[0.03] border border-white/10 rounded-xl px-5 py-3 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-violet-500/50 transition-colors font-mono text-sm"
                    />
                    <button
                        onClick={startScan}
                        disabled={!scanPath.trim() || status?.scanning}
                        className="px-6 py-3 bg-violet-600 hover:bg-violet-500 disabled:bg-violet-600/50 disabled:cursor-not-allowed text-white font-bold rounded-xl transition-all flex items-center gap-2 shadow-lg shadow-violet-500/20"
                    >
                        {status?.scanning ? (
                            <><Loader2 size={18} className="animate-spin" /> Scanning...</>
                        ) : (
                            <><FolderSearch size={18} /> Scan & Enrich</>
                        )}
                    </button>
                </div>

                {/* Progress Bar */}
                {status?.scanning && (
                    <div className="mt-4 relative z-10">
                        <div className="flex justify-between text-xs text-slate-400 mb-2">
                            <span>Processing {status.done} / {status.total} files</span>
                            <span>{status.progress.toFixed(1)}%</span>
                        </div>
                        <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-violet-500 to-purple-500 rounded-full transition-all duration-500"
                                style={{ width: `${status.progress}%` }}
                            />
                        </div>
                    </div>
                )}

                {/* Error Display */}
                {status?.error && !status.scanning && (
                    <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-3 text-sm text-red-400 relative z-10">
                        <AlertCircle size={16} />
                        {status.error}
                    </div>
                )}

                {/* Success Display */}
                {status && !status.scanning && !status.error && status.done > 0 && (
                    <div className="mt-4 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center gap-3 text-sm text-emerald-400 relative z-10">
                        <CheckCircle2 size={16} />
                        Enrichment complete — {status.done} files processed
                    </div>
                )}
            </div>

            {/* Results Table */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-8 backdrop-blur-xl">
                <div className="flex items-center justify-between mb-6">
                    <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                        <Film size={20} className="text-violet-400" />
                        Enriched Library
                    </h3>
                    <button
                        onClick={fetchResults}
                        className="text-xs text-violet-400 hover:text-violet-300 bg-violet-500/10 px-3 py-1.5 rounded-lg border border-violet-500/20 transition-colors"
                    >
                        Refresh
                    </button>
                </div>

                {isLoadingResults ? (
                    <div className="text-center py-16">
                        <Loader2 size={32} className="animate-spin mx-auto text-violet-400 mb-3" />
                        <p className="text-slate-500 text-sm">Loading enriched metadata...</p>
                    </div>
                ) : results.length === 0 ? (
                    <div className="text-center py-16">
                        <FolderSearch size={48} className="mx-auto text-slate-600 mb-4" />
                        <p className="text-slate-500">No enriched metadata yet. Scan a media directory to get started.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-white/[0.05]">
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">File</th>
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">Title</th>
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">Year</th>
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">Language</th>
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">Quality</th>
                                    <th className="text-left py-3 px-4 text-slate-500 font-medium text-xs uppercase tracking-wider">Subtitles</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((item) => {
                                    let subtitles: string[] = [];
                                    try { subtitles = JSON.parse(item.subtitles_json || '[]'); } catch { /* ignore */ }
                                    return (
                                        <tr key={item.id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors">
                                            <td className="py-3 px-4">
                                                <div className="flex items-center gap-2">
                                                    {getFileIcon(item.filename)}
                                                    <span className="text-slate-300 font-mono text-xs truncate max-w-[200px]" title={item.filename}>
                                                        {item.filename}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="py-3 px-4 text-slate-200 font-medium">{item.title || '—'}</td>
                                            <td className="py-3 px-4 text-slate-400">{item.year || '—'}</td>
                                            <td className="py-3 px-4">
                                                <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded-md text-xs border border-blue-500/20">
                                                    {item.language || 'unknown'}
                                                </span>
                                            </td>
                                            <td className="py-3 px-4">
                                                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded-md text-xs border border-emerald-500/20">
                                                    {item.quality || 'unknown'}
                                                </span>
                                            </td>
                                            <td className="py-3 px-4">
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
