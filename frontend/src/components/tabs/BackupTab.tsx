import { HardDriveDownload, Archive, CheckCircle2, Clock, ShieldCheck, Database } from 'lucide-react';
import { useState } from 'react';

interface BackupProgress {
    status: 'idle' | 'running' | 'success' | 'error';
    message: string;
    details?: {
        filename: string;
        size: number;
        timestamp: string;
    }
}

export default function BackupTab() {
    const [backupState, setBackupState] = useState<BackupProgress>({ status: 'idle', message: 'System healthy. Ready for manual snapshot.' });

    const handleRunBackup = async () => {
        setBackupState({ status: 'running', message: 'Initiating AetherFlow database snapshot...' });

        try {
            const res = await fetch('http://localhost:8080/api/backup/run', { method: 'POST' });
            const data = await res.json();

            if (res.ok) {
                setBackupState({
                    status: 'success',
                    message: data.message,
                    details: {
                        filename: data.filename,
                        size: data.size,
                        timestamp: data.timestamp
                    }
                });
            } else {
                throw new Error(data.error || 'Backup failed');
            }
        } catch (err: any) {
            setBackupState({ status: 'error', message: err.message || 'Network error triggering backup.' });
        }
    };

    const formatBytes = (bytes: number) => {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${['Bytes', 'KB', 'MB', 'GB'][i]}`;
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-[calc(100vh-10rem)] flex flex-col">

            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden flex-1">
                {/* Background glow */}
                <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-emerald-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/2"></div>

                <div className="flex items-center justify-between mb-8 pb-4 border-b border-white/5 relative z-10">
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <HardDriveDownload size={24} className="text-emerald-400" />
                        System Backups & Snapshots
                    </h2>
                    <div className="flex items-center gap-2 text-sm text-slate-400 bg-emerald-500/10 text-emerald-400 px-4 py-2 rounded-xl border border-emerald-500/20">
                        <ShieldCheck size={16} />
                        Automated weekly backups active
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 relative z-10">

                    {/* Manual Backup Trigger */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-3xl p-8 flex flex-col justify-between">
                        <div>
                            <div className="w-16 h-16 bg-emerald-500/10 rounded-2xl flex items-center justify-center text-emerald-400 mb-6 border border-emerald-500/20">
                                <Database size={32} />
                            </div>
                            <h3 className="text-xl font-bold text-slate-200 mb-2">Manual Snapshot</h3>
                            <p className="text-slate-400 text-sm leading-relaxed mb-8">
                                Triggers an immediate zero-downtime hot backup of the full AetherFlow SQLite database. Docker configs and proxy rules are simultaneously archived.
                            </p>
                        </div>

                        <button
                            onClick={handleRunBackup}
                            disabled={backupState.status === 'running'}
                            className={`w-full py-4 px-6 rounded-xl font-bold text-white shadow-xl transition-all flex items-center justify-center gap-3 ${backupState.status === 'running'
                                    ? 'bg-emerald-600/50 cursor-not-allowed'
                                    : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20 hover:scale-[1.02]'
                                }`}
                        >
                            {backupState.status === 'running' ? (
                                <>
                                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                    Snapshotting...
                                </>
                            ) : (
                                <>
                                    <Archive size={20} />
                                    Generate New Archive
                                </>
                            )}
                        </button>
                    </div>

                    {/* Status Console */}
                    <div className="bg-slate-900 border border-white/5 rounded-3xl p-8 shadow-inner flex flex-col">
                        <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-6 flex items-center gap-2">
                            <Clock size={16} /> Operation Status
                        </h3>

                        <div className="flex-1 flex flex-col justify-center">
                            {backupState.status === 'idle' && (
                                <div className="text-center text-slate-500">
                                    <HardDriveDownload size={48} className="mx-auto mb-4 opacity-50 text-slate-600" />
                                    <p>{backupState.message}</p>
                                </div>
                            )}

                            {backupState.status === 'running' && (
                                <div className="flex flex-col items-center justify-center animate-pulse text-emerald-400">
                                    <Database size={48} className="mb-4" />
                                    <p className="font-mono text-sm">{backupState.message}</p>
                                </div>
                            )}

                            {backupState.status === 'success' && backupState.details && (
                                <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-2xl p-6 relative overflow-hidden animate-fade-in">
                                    <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/20 rounded-full blur-3xl"></div>
                                    <div className="flex items-start gap-4 relative z-10">
                                        <div className="mt-1">
                                            <CheckCircle2 size={24} className="text-emerald-400" />
                                        </div>
                                        <div>
                                            <h4 className="text-emerald-400 font-bold text-lg mb-1">Backup Successful</h4>
                                            <p className="text-slate-300 text-sm mb-4">Database safely archived.</p>

                                            <div className="space-y-2 text-sm">
                                                <div className="flex justify-between border-b border-emerald-500/10 pb-2">
                                                    <span className="text-slate-500">Archive Name</span>
                                                    <span className="text-slate-200 font-mono text-xs">{backupState.details.filename}</span>
                                                </div>
                                                <div className="flex justify-between border-b border-emerald-500/10 pb-2">
                                                    <span className="text-slate-500">Payload Size</span>
                                                    <span className="text-slate-200 font-mono">{formatBytes(backupState.details.size)}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {backupState.status === 'error' && (
                                <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-6 text-center animate-fade-in">
                                    <div className="w-12 h-12 bg-red-500/20 text-red-400 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl font-bold">!</div>
                                    <h4 className="text-red-400 font-bold mb-2">Operation Failed</h4>
                                    <p className="text-slate-400 text-sm">{backupState.message}</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
