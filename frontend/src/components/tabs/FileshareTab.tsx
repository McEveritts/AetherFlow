import { useState, useRef } from 'react';
import useSWR from 'swr';
import { FolderUp, File as FileIcon, UploadCloud, Download, HardDrive, FolderOpen, X, ChevronRight } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';

interface FetchedFile {
    name: string;
    size: number;
    modTime: string;
    extension: string;
    isDir?: boolean;
}

export default function FileshareTab() {
    const [currentPath, setCurrentPath] = useState('/');
    
    const { data: files, error, mutate } = useSWR<FetchedFile[]>(`/api/v1/auth/fileshare?path=${encodeURIComponent(currentPath)}`);
    const [isDragging, setIsDragging] = useState(false);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const abortControllerRef = useRef<AbortController | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const { addToast } = useToast();

    const handleUpload = async (file: File) => {
        setIsUploading(true);
        setUploadProgress(0);
        abortControllerRef.current = new AbortController();

        const chunkSize = 50 * 1024 * 1024; // 50MB chunks
        const totalChunks = Math.ceil(file.size / chunkSize);

        try {
            const token = document.cookie.split('; ').find(row => row.startsWith('af_sid='))?.split('=')[1] || '';
            
            for (let i = 0; i < totalChunks; i++) {
                if (abortControllerRef.current.signal.aborted) throw new Error('aborted');

                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('file', chunk);
                
                const res = await fetch('/api/v1/admin/fileshare/upload', {
                    method: 'POST',
                    body: formData,
                    signal: abortControllerRef.current.signal,
                    headers: {
                        'Authorization': `Bearer ${token}`,
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

            addToast('File uploaded successfully.', 'success');
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

    const handleDownload = (filename: string) => {
        window.location.assign(`/api/v1/auth/fileshare/download/${encodeURIComponent(filename)}`);
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
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden flex flex-col h-[calc(100vh-10rem)]">

                {/* Background glow */}
                <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 translate-x-1/3"></div>

                <div className="flex items-center justify-between mb-8 pb-4 border-b border-white/5 relative z-10 shrink-0">
                    <div>
                        <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                            <FolderUp size={24} className="text-blue-400" />
                            Secure File Drop
                        </h2>
                        {files && (
                            <div className="mt-3 flex flex-col gap-1.5 w-[300px]">
                                <div className="flex justify-between text-xs font-semibold text-slate-400">
                                    <span>{formatBytes(files.reduce((acc, f) => acc + f.size, 0))} Used</span>
                                    <span>50 GB Total</span>
                                </div>
                                <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                                    <div 
                                        className="h-full bg-blue-500 rounded-full transition-all duration-500" 
                                        style={{ width: `${Math.min((files.reduce((acc, f) => acc + f.size, 0) / (50 * 1024 * 1024 * 1024)) * 100, 100)}%` }}
                                    ></div>
                                </div>
                            </div>
                        )}
                    </div>
                    <div className="flex items-center gap-2 text-sm text-slate-400 bg-white/5 px-4 py-2 rounded-xl h-fit">
                        <HardDrive size={16} />
                        Local Storage
                    </div>
                </div>

                <div className="flex gap-6 relative z-10 flex-1 min-h-0">
                    {/* Upload Zone */}
                    <div
                        className={`w-1/3 flex flex-col items-center justify-center border-2 border-dashed rounded-3xl transition-all duration-300 p-8 text-center ${isDragging ? 'border-blue-500 bg-blue-500/10 scale-[1.02]' : 'border-white/10 hover:border-white/20 hover:bg-white/[0.02]'}`}
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
                        <div className={`w-20 h-20 rounded-full flex items-center justify-center mb-6 transition-colors ${isDragging ? 'bg-blue-500/20 text-blue-400' : 'bg-white/5 text-slate-400'}`}>
                            <UploadCloud size={32} />
                        </div>
                        <h3 className="text-lg font-bold text-slate-200 mb-2">Drag & Drop Files</h3>
                        <p className="text-sm text-slate-400 mb-8 max-w-[200px]">Securely upload files to the AetherFlow internal network dropsite.</p>

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
                        <div className="flex flex-col gap-2 w-full">
                            {isUploading ? (
                                <div className="p-4 bg-white/[0.04] border border-white/10 rounded-xl relative overflow-hidden group">
                                    <div className="flex items-center justify-between mb-2 z-10 relative">
                                        <span className="text-sm font-bold text-blue-400">Uploading chunks...</span>
                                        <div className="flex items-center gap-3">
                                            <span className="text-xs text-slate-400 font-mono">{uploadProgress}%</span>
                                            <button onClick={cancelUpload} className="p-1 rounded bg-white/5 hover:bg-red-500/20 hover:text-red-400 text-slate-400 transition-colors">
                                                <X size={14} />
                                            </button>
                                        </div>
                                    </div>
                                    <div className="w-full bg-slate-900 rounded-full h-1.5 z-10 relative">
                                        <div className="bg-blue-500 h-1.5 rounded-full transition-all duration-300" style={{ width: `${uploadProgress}%` }}></div>
                                    </div>
                                </div>
                            ) : (
                                <button
                                    onClick={() => fileInputRef.current?.click()}
                                    className="px-6 py-3 w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-blue-500/20"
                                >
                                    Browse Local Files
                                </button>
                            )}
                        </div>
                    </div>

                    {/* File List */}
                    <div className="flex-1 bg-slate-950/50 border border-white/10 rounded-3xl p-6 flex flex-col overflow-hidden">
                        <div className="flex items-center gap-2 text-sm font-bold text-slate-400 uppercase tracking-wider mb-6 shrink-0 bg-white/[0.02] p-2 rounded-lg border border-white/5">
                            <button onClick={() => setCurrentPath('/')} className="hover:text-blue-400 cursor-pointer">Root</button>
                            {currentPath !== '/' && currentPath.split('/').filter(Boolean).map((part, idx, arr) => (
                                <div key={idx} className="flex items-center gap-2">
                                    <ChevronRight size={14} className="text-slate-600" />
                                    <button 
                                        onClick={() => setCurrentPath('/' + arr.slice(0, idx+1).join('/'))}
                                        className="hover:text-blue-400 cursor-pointer"
                                    >
                                        {part}
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="flex-1 overflow-y-auto pr-2 space-y-3 no-scrollbar transform translate-z-0">
                            {error ? (
                                <div className="text-center p-10 text-red-400">Error loading files</div>
                            ) : !files ? (
                                <div className="flex justify-center p-10">
                                    <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin"></div>
                                </div>
                            ) : files.length === 0 ? (
                                <div className="flex flex-col items-center justify-center h-full text-slate-500">
                                    <FolderUp size={48} className="mb-4 opacity-50 text-slate-600" />
                                    <p>The shared drive is currently empty.</p>
                                </div>
                            ) : (
                                files.map((file, i) => (
                                    <div key={i} className="flex items-center justify-between p-4 bg-white/[0.02] hover:bg-white/[0.04] border border-white/5 rounded-2xl transition-colors group">
                                        <div className="flex items-center gap-4 flex-1">
                                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${file.isDir ? 'bg-amber-500/10 text-amber-400' : 'bg-blue-500/10 text-blue-400'}`}>
                                                {file.isDir ? <FolderOpen size={20} /> : <FileIcon size={20} />}
                                            </div>
                                            <div className="flex-1">
                                                {file.isDir ? (
                                                    <button 
                                                        onClick={() => setCurrentPath(currentPath === '/' ? `/${file.name}` : `${currentPath}/${file.name}`)}
                                                        className="text-sm font-bold text-slate-200 hover:text-blue-400 transition-colors text-left"
                                                    >
                                                        {file.name}
                                                    </button>
                                                ) : (
                                                    <p className="text-sm font-bold text-slate-200">{file.name}</p>
                                                )}
                                                <div className="flex gap-3 text-xs text-slate-500 mt-1">
                                                    {!file.isDir && <span>{formatBytes(file.size)}</span>}
                                                    {!file.isDir && <span>&bull;</span>}
                                                    <span>{new Date(file.modTime).toLocaleDateString()}</span>
                                                </div>
                                            </div>
                                        </div>
                                        {!file.isDir && (
                                            <button
                                                onClick={() => handleDownload(file.name)}
                                                className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors opacity-0 group-hover:opacity-100 flex items-center justify-center"
                                                title="Download File"
                                            >
                                                <Download size={18} />
                                            </button>
                                        )}
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}
