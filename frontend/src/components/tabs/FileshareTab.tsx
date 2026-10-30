import { useState, useRef } from 'react';
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

    const totalUsedBytes = Array.isArray(files) ? files.reduce((acc, f) => acc + (f.size || 0), 0) : 0;
    const totalCapacityBytes = 50 * 1024 * 1024 * 1024; // 50 GB
    const usedPercentage = Math.min((totalUsedBytes / totalCapacityBytes) * 100, 100);
    const fileCount = Array.isArray(files) ? files.filter(f => !f.isDir).length : 0;
    const dirCount = Array.isArray(files) ? files.filter(f => f.isDir).length : 0;

    const handleUpload = async (file: File) => {
        setIsUploading(true);
        setUploadProgress(0);
        abortControllerRef.current = new AbortController();

        const chunkSize = 50 * 1024 * 1024; // 50MB chunks
        const totalChunks = Math.ceil(file.size / chunkSize);

        try {
            for (let i = 0; i < totalChunks; i++) {
                if (abortControllerRef.current.signal.aborted) throw new Error('aborted');

                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('file', chunk, file.name);
                
                const res = await apiFetch('/api/v1/admin/fileshare/upload', {
                    method: 'POST',
                    body: formData,
                    signal: abortControllerRef.current.signal,
                    headers: {
                        'X-Chunk-Index': i.toString(),
                        'X-Total-Chunks': totalChunks.toString(),
                        'X-Target-Path': currentPath,
                        'X-File-Name': file.name
                    }
                });

                if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    throw new Error(data.error || 'Chunk upload failed');
                }

                setUploadProgress(Math.round(((i + 1) / totalChunks) * 100));
            }

            addToast(`Uploaded ${file.name} successfully`, 'success');
            mutate();
        } catch (err) {
            if (abortControllerRef.current?.signal.aborted || (err instanceof Error && err.message === 'aborted')) {
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
                throw new Error(data.error || 'Failed to delete file');
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
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-blue-500/20 border-blue-500/30 shadow-[0_0_20px_rgba(59,130,246,0.15)] text-blue-400">
                        <FolderUp size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Secure File Share</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-blue-500/15 text-blue-300 border-blue-500/30">
                                Local Storage
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Live Filesystem · {Array.isArray(files) ? files.length : 0} items indexed ({currentPath})
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        onClick={() => fileInputRef.current?.click()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-blue-500/20 border border-blue-500/30 text-blue-300 hover:bg-blue-500/30 transition-all shadow-lg shadow-blue-500/10"
                    >
                        <UploadCloud size={14} />
                        <span>Upload File</span>
                    </button>
                    <button
                        onClick={() => mutate()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Directory"
                    >
                        <RefreshCw size={14} className={isValidating ? 'animate-spin text-blue-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Open Storage Summary Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Used Capacity</span>
                        <HardDrive size={18} className="text-blue-400" />
                    </div>
                    <div className="mt-2">
                        <div className="flex items-baseline justify-between mb-1.5">
                            <span className="text-xl font-bold text-slate-100">{formatBytes(totalUsedBytes)}</span>
                            <span className="text-xs font-semibold text-blue-400">{usedPercentage.toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-blue-500 rounded-full transition-all duration-500"
                                style={{ width: `${usedPercentage}%` }}
                            ></div>
                        </div>
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Capacity</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">50 GB</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Hardware NVMe Pool</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <FolderOpen size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Files</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{fileCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">{dirCount} Subdirectories</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <FileIcon size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Upload Status</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {isUploading ? `Uploading ${uploadProgress}%` : 'Ready / Idle'}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-0.5">50MB Chunk Streaming</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                        {isUploading ? <Loader2 size={20} className="animate-spin" /> : <UploadCloud size={20} />}
                    </div>
                </div>
            </div>

            {/* Main Content: Upload Dropzone & File Browser */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Upload Dropzone */}
                <div
                    className={`rounded-2xl border border-dashed transition-all duration-300 p-6 md:p-8 flex flex-col items-center justify-center text-center bg-slate-900/30 backdrop-blur-xl ${
                        isDragging
                            ? 'border-blue-500 bg-blue-500/10 scale-[1.01]'
                            : 'border-white/[0.12] hover:border-white/20 hover:bg-slate-900/40'
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
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center mb-4 transition-colors ${
                        isDragging ? 'bg-blue-500/20 text-blue-400' : 'bg-white/[0.04] border border-white/[0.06] text-slate-400'
                    }`}>
                        <UploadCloud size={28} />
                    </div>
                    <h3 className="text-base font-bold text-slate-100 mb-1">Drag & Drop Files</h3>
                    <p className="text-xs text-slate-400 mb-6 max-w-[220px]">
                        Upload files with automatic 50MB chunking directly to target directory.
                    </p>

                    <input
                        type="file"
                        className="hidden"
                        ref={fileInputRef}
                        onChange={(e) => {
                            if (e.target.files && e.target.files[0]) {
                                handleUpload(e.target.files[0]);
                            }
                        }}
                    />

                    <div className="w-full">
                        {isUploading ? (
                            <div className="p-3.5 bg-white/[0.04] border border-white/10 rounded-xl relative overflow-hidden">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs font-bold text-blue-400 flex items-center gap-1.5">
                                        <Loader2 size={13} className="animate-spin" />
                                        Streaming Chunks...
                                    </span>
                                    <div className="flex items-center gap-2">
                                        <span className="text-xs text-slate-400 font-mono">{uploadProgress}%</span>
                                        <button
                                            onClick={cancelUpload}
                                            className="p-1 rounded bg-white/5 hover:bg-red-500/20 hover:text-red-400 text-slate-400 transition-colors"
                                            title="Cancel Upload"
                                        >
                                            <X size={12} />
                                        </button>
                                    </div>
                                </div>
                                <div className="w-full bg-slate-900 rounded-full h-1.5">
                                    <div
                                        className="bg-blue-500 h-1.5 rounded-full transition-all duration-300"
                                        style={{ width: `${uploadProgress}%` }}
                                    ></div>
                                </div>
                            </div>
                        ) : (
                            <button
                                onClick={() => fileInputRef.current?.click()}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2.5 w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-blue-500/20 text-xs tracking-wide"
                            >
                                Browse Local Files
                            </button>
                        )}
                    </div>
                </div>

                {/* File Browser Table */}
                <div className="lg:col-span-2 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col">
                    {/* Path Breadcrumbs & Selector */}
                    <div className="relative z-20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-white/[0.06]">
                        <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-wider overflow-x-auto max-w-full obs-touch-pills">
                            <button onClick={() => setCurrentPath('/')} className="hover:text-blue-400 cursor-pointer py-1 px-1.5 rounded hover:bg-white/[0.04]">Root</button>
                            {currentPath !== '/' && currentPath.split('/').filter(Boolean).map((part, idx, arr) => (
                                <div key={idx} className="flex items-center gap-1.5">
                                    <ChevronRight size={12} className="text-slate-600" />
                                    <button
                                        onClick={() => setCurrentPath('/' + arr.slice(0, idx + 1).join('/'))}
                                        className="hover:text-blue-400 cursor-pointer py-1 px-1.5 rounded hover:bg-white/[0.04]"
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
                            className="w-full sm:w-60 shrink-0 text-xs"
                        />
                    </div>

                    {/* File Rows List */}
                    <div className="flex-1 overflow-y-auto space-y-2 max-h-[500px] pr-1">
                        {error ? (
                            <div className="text-center py-12 text-xs text-red-400">
                                Error reading filesystem: {error instanceof Error ? error.message : 'Unknown error'}
                            </div>
                        ) : isLoading || !files ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                                <Loader2 size={32} className="text-blue-500/40 mb-2 animate-spin" />
                                <span className="text-xs">Loading directory contents...</span>
                            </div>
                        ) : Array.isArray(files) && files.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                                <FolderUp size={36} className="mb-2 text-slate-600" />
                                <p className="text-sm font-semibold text-slate-300">Directory is empty</p>
                                <p className="text-xs text-slate-500 mt-0.5">Drop files to start sharing</p>
                            </div>
                        ) : (
                            Array.isArray(files) && files.map((file, i) => (
                                <div
                                    key={i}
                                    className="flex items-center justify-between p-3 rounded-xl border border-white/[0.04] bg-white/[0.02] hover:bg-white/[0.04] hover:border-white/[0.08] transition-all group"
                                >
                                    <div className="flex items-center gap-3.5 flex-1 min-w-0">
                                        <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${file.isDir ? 'bg-amber-500/10 text-amber-400' : 'bg-blue-500/10 text-blue-400'}`}>
                                            {file.isDir ? <FolderOpen size={18} /> : <FileIcon size={18} />}
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            {file.isDir ? (
                                                <button
                                                    onClick={() => setCurrentPath(currentPath === '/' ? `/${file.name}` : `${currentPath}/${file.name}`)}
                                                    className="text-xs font-bold text-slate-200 hover:text-blue-400 transition-colors text-left truncate block w-full"
                                                >
                                                    {file.name}
                                                </button>
                                            ) : (
                                                <p className="text-xs font-bold text-slate-200 truncate">{file.name}</p>
                                            )}
                                            <div className="flex items-center gap-2 text-[11px] text-slate-500 mt-0.5">
                                                {!file.isDir && <span>{formatBytes(file.size)}</span>}
                                                {!file.isDir && <span>&bull;</span>}
                                                <span>{new Date(file.modTime).toLocaleDateString()}</span>
                                            </div>
                                        </div>
                                    </div>

                                    {!file.isDir && (
                                        <div className="flex items-center gap-1.5 shrink-0 ml-3">
                                            <button
                                                onClick={() => handleDownload(file.name)}
                                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-blue-400 hover:bg-white/[0.06] rounded-lg transition-all"
                                                title="Download File"
                                            >
                                                <Download size={15} />
                                            </button>
                                            <button
                                                onClick={() => handleDelete(file.name)}
                                                disabled={deletingFile === file.name}
                                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all disabled:opacity-50"
                                                title="Delete File"
                                            >
                                                {deletingFile === file.name ? <Loader2 size={15} className="animate-spin text-red-400" /> : <Trash2 size={15} />}
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
