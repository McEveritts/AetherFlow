import { useState, useRef, useEffect } from 'react';
import useSWR from 'swr';
import { FolderUp, File as FileIcon, UploadCloud, Download, HardDrive, FolderOpen, X, ChevronRight, Trash2, RefreshCw, Loader2 } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { apiFetch } from '@/lib/fetcher';
import PathSelector from '@/components/ui/PathSelector';

interface FetchedFile {
    name: string;
    size: number;
    modTime: string;
    extension: string;
    isDir?: boolean;
}

export default function FileshareTab() {
    const [currentPath, setCurrentPath] = useState('/');
    
    const { data: files, error, isLoading, isValidating, mutate } = useSWR<FetchedFile[]>(`/api/v1/auth/fileshare?path=${encodeURIComponent(currentPath)}`);
    const [isDragging, setIsDragging] = useState(false);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [deletingFile, setDeletingFile] = useState<string | null>(null);
    const abortControllerRef = useRef<AbortController | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const { addToast } = useToast();

    useEffect(() => () => abortControllerRef.current?.abort(), []);

    const totalUsedBytes = Array.isArray(files) ? files.reduce((acc, f) => acc + (f.size || 0), 0) : 0;
    const totalCapacityBytes = 50 * 1024 * 1024 * 1024; // 50 GB
    const usedPercentage = Math.min((totalUsedBytes / totalCapacityBytes) * 100, 100);
    const fileCount = Array.isArray(files) ? files.filter(f => !f.isDir).length : 0;
    const dirCount = Array.isArray(files) ? files.filter(f => f.isDir).length : 0;

    const handleUpload = async (file: File) => {
        if (abortControllerRef.current) return;
        if (file.size > 50 * 1024 * 1024) {
            addToast('File exceeds the 50 MiB upload limit.', 'error');
            return;
        }
        setIsUploading(true);
        setUploadProgress(0);
        const controller = new AbortController();
        abortControllerRef.current = controller;

        const chunkSize = 5 * 1024 * 1024;
        const totalChunks = Math.max(1, Math.ceil(file.size / chunkSize));
        const uploadId = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');

        try {
            for (let i = 0; i < totalChunks; i++) {
                if (controller.signal.aborted) throw new Error('aborted');

                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('file', chunk, file.name);
                
                const res = await apiFetch('/api/v1/admin/fileshare/upload', {
                    method: 'POST',
                    body: formData,
                    signal: controller.signal,
                    headers: {
                        'X-Upload-ID': uploadId,
                        'X-Chunk-Index': i.toString(),
                        'X-Total-Chunks': totalChunks.toString(),
                        'X-Target-Path': currentPath,
                        'X-File-Name': file.name
                    }
                });

                if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    throw new Error(data.error || data.message || 'Chunk upload failed');
                }

                setUploadProgress(Math.round(((i + 1) / totalChunks) * 100));
            }

            addToast(`Uploaded ${file.name} successfully`, 'success');
            mutate();
        } catch (err) {
            if (controller.signal.aborted || (err instanceof Error && err.message === 'aborted')) {
                addToast('Upload cancelled.', 'info');
            } else {
                console.error("Upload failed", err);
                addToast(err instanceof Error ? err.message : 'Upload failed', 'error');
            }
        } finally {
            setIsUploading(false);
            setUploadProgress(0);
            abortControllerRef.current = null;
        }
    };

    const cancelUpload = () => {
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
    };

    const handleDelete = async (filename: string) => {
        if (!confirm(`Are you sure you want to delete ${filename}?`)) return;
        setDeletingFile(filename);
        try {
            const res = await apiFetch(`/api/v1/admin/fileshare/${encodeURIComponent(filename)}?path=${encodeURIComponent(currentPath)}`, {
                method: 'DELETE'
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || data.message || 'Failed to delete file');
            }
            addToast(`Deleted ${filename}`, 'success');
            mutate();
        } catch (err) {
            addToast(err instanceof Error ? err.message : 'Delete failed', 'error');
        } finally {
            setDeletingFile(null);
        }
    };

    const handleDownload = (filename: string) => {
        window.location.assign(`/api/v1/auth/fileshare/download/${encodeURIComponent(filename)}?path=${encodeURIComponent(currentPath)}`);
    };

    const formatBytes = (bytes: number, decimals = 2) => {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    };

    return (
        <div className="animate-fade-in relative z-10 w-full min-w-0 max-w-full">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.07] relative z-30 shrink-0">
                <div className="flex items-center gap-3 min-w-0">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-cyan-500/15 border-cyan-500/30 shadow-[0_0_20px_rgba(6,182,212,0.15)] text-cyan-400 shrink-0">
                        <FolderUp size={20} />
                    </div>
                    <div className="min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                            <h2 className="text-base sm:text-lg md:text-xl font-extrabold text-slate-100 tracking-tight">Secure File Share</h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-cyan-500/15 text-cyan-300 border-cyan-500/30">
                                Local Storage
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5 shrink-0">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400 animate-pulse"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide truncate">
                                Live Filesystem &middot; {Array.isArray(files) ? files.length : 0} items indexed ({currentPath})
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        aria-label="Upload File"
                        className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/30 transition-all focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:outline-none"
                    >
                        <UploadCloud size={14} />
                        <span>Upload File</span>
                    </button>
                    <button
                        type="button"
                        onClick={() => mutate()}
                        aria-label="Refresh Directory"
                        className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] sm:min-h-[40px] flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:outline-none"
                        title="Refresh Directory"
                    >
                        <RefreshCw size={14} className={isValidating ? 'animate-spin text-cyan-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            <div className="obs-metric-strip">
                <div className="p-4 sm:p-5 flex flex-col justify-between min-w-0">
                    <div className="flex items-center justify-between min-w-0">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                            Used Capacity
                        </span>
                        <HardDrive size={18} className="text-cyan-400 shrink-0 ml-2" />
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline justify-between mb-1.5">
                            <span className="text-xl sm:text-2xl font-bold font-mono text-slate-100 truncate">{formatBytes(totalUsedBytes)}</span>
                            <span className="text-xs font-semibold font-mono text-cyan-400 shrink-0">{usedPercentage.toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                                style={{ width: `${usedPercentage}%` }}
                            ></div>
                        </div>
                    </div>
                </div>

                <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                    <div className="min-w-0 flex-1">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                            Total Capacity
                        </span>
                        <div className="text-xl sm:text-2xl font-bold font-mono text-slate-100 mt-1 break-words">
                            50 GB
                        </div>
                        <span className="text-xs text-slate-500 mt-0.5 block break-words">
                            Hardware NVMe Pool
                        </span>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0 ml-3">
                        <FolderOpen size={18} />
                    </div>
                </div>

                <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                    <div className="min-w-0 flex-1">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                            Total Files
                        </span>
                        <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1 break-words">
                            {fileCount}
                        </div>
                        <span className="text-xs text-slate-500 mt-0.5 block break-words">
                            {dirCount} Subdirectories
                        </span>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0 ml-3">
                        <FileIcon size={18} />
                    </div>
                </div>

                <div className="p-4 sm:p-5 flex items-center justify-between min-w-0">
                    <div className="min-w-0 flex-1">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block break-words">
                            Upload Status
                        </span>
                        <div className="text-base sm:text-lg font-bold font-mono text-purple-300 mt-1 break-words">
                            {isUploading ? `Uploading ${uploadProgress}%` : 'Ready / Idle'}
                        </div>
                        <span className="text-xs text-slate-500 mt-0.5 block break-words">
                            50MB Chunk Streaming
                        </span>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0 ml-3">
                        {isUploading ? <Loader2 size={18} className="animate-spin" /> : <UploadCloud size={18} />}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 border-b border-white/[0.07] divide-y lg:divide-y-0 lg:divide-x divide-white/[0.07] items-stretch">
                <div className="lg:col-span-4 p-5 flex flex-col justify-between min-w-0 bg-white/[0.005]">
                    <div>
                        <div className="flex items-center gap-2 mb-3">
                            <UploadCloud size={16} className="text-cyan-400" />
                            <h3 className="text-xs sm:text-sm font-bold text-slate-200">Upload Dispatch</h3>
                        </div>

                        <div
                            className={`border border-dashed transition-all duration-300 p-6 flex flex-col items-center justify-center text-center rounded-xl bg-white/[0.01] ${
                                isDragging
                                    ? 'border-cyan-400 bg-cyan-500/10'
                                    : 'border-white/[0.12] hover:border-white/25 hover:bg-white/[0.02]'
                            }`}
                            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                            onDragLeave={() => setIsDragging(false)}
                            onDrop={(e) => {
                                e.preventDefault();
                                setIsDragging(false);
                                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                                    handleUpload(e.dataTransfer.files[0]);
                                }
                            }}
                        >
                            <div className={`w-14 h-14 rounded-xl flex items-center justify-center mb-3 transition-colors ${
                                isDragging ? 'bg-cyan-500/20 text-cyan-300' : 'bg-white/[0.04] border border-white/[0.08] text-slate-400'
                            }`}>
                                <UploadCloud size={24} />
                            </div>
                            <h4 className="text-sm font-bold text-slate-100 mb-1">Drag & Drop Files</h4>
                            <p className="text-xs text-slate-400 mb-4 max-w-[220px]">
                                Upload files with automatic 5MB chunking directly to {currentPath}
                            </p>

                            <input
                                type="file"
                                aria-label="Select file to upload"
                                className="hidden"
                                ref={fileInputRef}
                                onChange={(e) => {
                                    if (e.target.files && e.target.files[0]) {
                                        handleUpload(e.target.files[0]);
                                        e.target.value = '';
                                    }
                                }}
                            />

                            <div className="w-full">
                                {isUploading ? (
                                    <div className="p-3 bg-white/[0.04] border border-white/10 rounded-lg relative overflow-hidden">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                                                <Loader2 size={13} className="animate-spin" />
                                                Streaming Chunks...
                                            </span>
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs text-slate-300 font-mono">{uploadProgress}%</span>
                                                <button
                                                    type="button"
                                                    onClick={cancelUpload}
                                                    className="obs-touch-target-standard p-1 rounded bg-white/5 hover:bg-rose-500/20 hover:text-rose-400 text-slate-400 transition-colors flex items-center justify-center min-h-[44px] min-w-[44px] sm:min-h-[32px] sm:min-w-[32px]"
                                                    title="Cancel Upload"
                                                    aria-label="Cancel Upload"
                                                >
                                                    <X size={12} />
                                                </button>
                                            </div>
                                        </div>
                                        <div className="w-full bg-slate-900 rounded-full h-1.5">
                                            <div
                                                className="bg-cyan-500 h-1.5 rounded-full transition-all duration-300"
                                                style={{ width: `${uploadProgress}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                ) : (
                                    <button
                                        type="button"
                                        onClick={() => fileInputRef.current?.click()}
                                        className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] px-4 py-2.5 w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg transition-all shadow-sm text-xs tracking-wide flex items-center justify-center gap-2 focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:outline-none"
                                    >
                                        <UploadCloud size={14} />
                                        <span>Browse Local Files</span>
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-white/[0.06] text-xs text-slate-500">
                        Max file limit: 50 MiB &middot; High-concurrency upload guards active
                    </div>
                </div>

                <div className="lg:col-span-8 flex flex-col min-w-0 bg-white/[0.005]">
                    {/* Path Breadcrumbs & Selector */}
                    <div className="relative z-20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.07] bg-white/[0.01]">
                        <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-wider overflow-x-auto max-w-full obs-touch-pills">
                            <button
                                type="button"
                                onClick={() => setCurrentPath('/')}
                                className="obs-touch-target-standard min-h-[44px] hover:text-cyan-400 cursor-pointer py-1.5 px-2 rounded hover:bg-white/[0.04] transition-colors focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:outline-none"
                            >
                                Root
                            </button>
                            {currentPath !== '/' && currentPath.split('/').filter(Boolean).map((part, idx, arr) => (
                                <div key={idx} className="flex items-center gap-1.5">
                                    <ChevronRight size={12} className="text-slate-600" />
                                    <button
                                        type="button"
                                        onClick={() => setCurrentPath('/' + arr.slice(0, idx + 1).join('/'))}
                                        className="obs-touch-target-standard min-h-[44px] hover:text-cyan-400 cursor-pointer py-1.5 px-2 rounded hover:bg-white/[0.04] transition-colors focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:outline-none"
                                    >
                                        {part}
                                    </button>
                                </div>
                            ))}
                        </div>
                        <PathSelector
                            value={currentPath}
                            onChange={setCurrentPath}
                            placeholder="Jump to path..."
                            className="w-full sm:w-64 shrink-0 text-xs"
                        />
                    </div>

                    {/* File Rows List */}
                    <div className="flex-1 overflow-y-auto divide-y divide-white/[0.06] max-h-[560px]">
                        {error ? (
                            <div className="text-center py-16 px-4 text-xs text-rose-300">
                                Error reading filesystem: {error instanceof Error ? error.message : 'Unknown error'}
                            </div>
                        ) : isLoading || !files ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-400">
                                <Loader2 size={32} className="text-cyan-400 mb-2 animate-spin" />
                                <span className="text-xs">Loading directory contents...</span>
                            </div>
                        ) : Array.isArray(files) && files.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-400 text-center px-4">
                                <FolderUp size={36} className="mb-2 text-slate-500" />
                                <p className="text-sm font-semibold text-slate-300">Directory is empty</p>
                                <p className="text-xs text-slate-500 mt-0.5">Drop files to start sharing</p>
                            </div>
                        ) : (
                            Array.isArray(files) && files.map((file, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between px-5 py-3.5 hover:bg-white/[0.02] transition-colors group"
                                >
                                    <div className="flex items-center gap-3.5 flex-1 min-w-0">
                                        <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${file.isDir ? 'bg-amber-500/10 text-amber-400' : 'bg-cyan-500/10 text-cyan-400'}`}>
                                            {file.isDir ? <FolderOpen size={18} /> : <FileIcon size={18} />}
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            {file.isDir ? (
                                                <button
                                                    type="button"
                                                    onClick={() => setCurrentPath(currentPath === '/' ? `/${file.name}` : `${currentPath}/${file.name}`)}
                                                    className="text-xs font-bold text-slate-200 hover:text-cyan-300 transition-colors text-left break-words [overflow-wrap:anywhere] block w-full obs-touch-target-standard focus-visible:outline-none focus-visible:underline"
                                                >
                                                    {file.name}
                                                </button>
                                            ) : (
                                                <p className="text-xs font-bold text-slate-200 break-words [overflow-wrap:anywhere]" title={file.name}>{file.name}</p>
                                            )}
                                            <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5 font-mono">
                                                {!file.isDir && <span>{formatBytes(file.size)}</span>}
                                                {!file.isDir && <span>&bull;</span>}
                                                <span>{new Date(file.modTime).toLocaleDateString()}</span>
                                            </div>
                                        </div>
                                    </div>

                                    {!file.isDir && (
                                        <div className="flex items-center gap-1.5 shrink-0 ml-3">
                                            <button
                                                type="button"
                                                onClick={() => handleDownload(file.name)}
                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] sm:min-h-[44px] sm:min-w-[44px] p-2 text-slate-400 hover:text-cyan-300 hover:bg-white/[0.06] rounded-lg transition-all flex items-center justify-center"
                                                title="Download File"
                                                aria-label={`Download ${file.name}`}
                                            >
                                                <Download size={15} />
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => handleDelete(file.name)}
                                                disabled={deletingFile === file.name}
                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] sm:min-h-[44px] sm:min-w-[44px] p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all disabled:opacity-50 flex items-center justify-center"
                                                title="Delete File"
                                                aria-label={`Delete ${file.name}`}
                                            >
                                                {deletingFile === file.name ? <Loader2 size={15} className="animate-spin text-rose-400" /> : <Trash2 size={15} />}
                                            </button>
                                        </div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
