import { useState, useRef } from 'react';
import useSWR from 'swr';
import { FolderUp, File as FileIcon, UploadCloud, Download, HardDrive } from 'lucide-react';

const fetcher = (url: string) => fetch(url).then(res => res.json());

interface FetchedFile {
    name: string;
    size: number;
    modTime: string;
    extension: string;
}

export default function FileshareTab() {
    const { data: files, error, mutate } = useSWR<FetchedFile[]>('http://localhost:8080/api/fileshare', fetcher);
    const [isDragging, setIsDragging] = useState(false);
    const [isUploading, setIsUploading] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleUpload = async (file: File) => {
        setIsUploading(true);
        const formData = new FormData();
        formData.append('file', file);
        try {
            const res = await fetch('http://localhost:8080/api/fileshare/upload', {
                method: 'POST',
                body: formData
            });
            if (res.ok) {
                mutate();
            }
        } catch (err) {
            console.error("Upload failed", err);
        } finally {
            setIsUploading(false);
        }
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
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <FolderUp size={24} className="text-blue-400" />
                        Secure File Drop
                    </h2>
                    <div className="flex items-center gap-2 text-sm text-slate-400 bg-white/5 px-4 py-2 rounded-xl">
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
                        <button
                            onClick={() => fileInputRef.current?.click()}
                            disabled={isUploading}
                            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-500/50 text-white font-bold rounded-xl transition-all shadow-lg shadow-blue-500/20"
                        >
                            {isUploading ? 'Uploading...' : 'Browse Local Files'}
                        </button>
                    </div>

                    {/* File List */}
                    <div className="flex-1 bg-slate-950/50 border border-white/10 rounded-3xl p-6 flex flex-col overflow-hidden">
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-6 shrink-0">Network Drive Contents</h3>

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
                                        <div className="flex items-center gap-4">
                                            <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-400">
                                                <FileIcon size={20} />
                                            </div>
                                            <div>
                                                <p className="text-sm font-bold text-slate-200">{file.name}</p>
                                                <div className="flex gap-3 text-xs text-slate-500 mt-1">
                                                    <span>{formatBytes(file.size)}</span>
                                                    <span>•</span>
                                                    <span>{new Date(file.modTime).toLocaleDateString()}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <button className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors opacity-0 group-hover:opacity-100">
                                            <Download size={18} />
                                        </button>
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
