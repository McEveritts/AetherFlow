import { HardDriveDownload, Archive, CheckCircle2, Clock, ShieldCheck, Database, Download, BrainCircuit, Loader2, ToggleLeft, ToggleRight } from 'lucide-react';
import { useState, useEffect } from 'react';

interface BackupProgress {
    status: 'idle' | 'running' | 'success' | 'error';
    message: string;
    details?: {
        filename: string;
        size: number;
        timestamp: string;
    }
}

interface BackupFile {
    filename: string;
    size: number;
    timestamp: string;
}

interface BackupWindow {
    optimal_hour: number;
    duration_mins: number;
    confidence: number;
    reasoning: string;
    timezone: string;
}

interface ScheduleStatus {
    mode: string;
    running: boolean;
    optimal_window?: BackupWindow;
    next_backup_at?: string;
}

export default function BackupTab() {
    const [backupState, setBackupState] = useState<BackupProgress>({ status: 'idle', message: 'System healthy. Ready for manual snapshot.' });
    const [backups, setBackups] = useState<BackupFile[]>([]);
    const [isLoadingBackups, setIsLoadingBackups] = useState(true);
    const [schedule, setSchedule] = useState<ScheduleStatus | null>(null);
    const [isTogglingSchedule, setIsTogglingSchedule] = useState(false);

    const fetchBackups = async () => {
        setIsLoadingBackups(true);
        try {
            const res = await fetch('/api/backup/list');
            if (res.ok) {
                const data = await res.json();
                setBackups(data.sort((a: BackupFile, b: BackupFile) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
            }
        } catch (err) {
            console.error("Failed to fetch backups", err);
        } finally {
            setIsLoadingBackups(false);
        }
    };

    const fetchSchedule = async () => {
        try {
            const res = await fetch('/api/ai/backup/optimal-window');
            if (res.ok) {
                const data: ScheduleStatus = await res.json();
                setSchedule(data);
            }
        } catch {
            // Smart scheduling may not be available
        }
    };

    useEffect(() => {
        fetchBackups();
        fetchSchedule();
    }, []);

    const handleRunBackup = async () => {
        setBackupState({ status: 'running', message: 'Initiating AetherFlow database snapshot...' });

        try {
            const res = await fetch('/api/backup/run', { method: 'POST' });
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
                fetchBackups();
            } else {
                throw new Error(data.error || 'Backup failed');
            }
        } catch (err: unknown) {
            setBackupState({ status: 'error', message: err instanceof Error ? err.message : 'Network error triggering backup.' });
        }
    };

    const toggleSmartSchedule = async () => {
        if (!schedule) return;
        setIsTogglingSchedule(true);
        const newMode = schedule.mode === 'smart' ? 'manual' : 'smart';
        try {
            const res = await fetch('/api/ai/backup/schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: newMode })
            });
            if (res.ok) {
                setSchedule(prev => prev ? { ...prev, mode: newMode } : null);
                // Re-fetch after a delay to get the computed window
                setTimeout(fetchSchedule, 3000);
            }
        } catch {
            console.error("Failed to toggle schedule");
        } finally {
            setIsTogglingSchedule(false);
        }
    };

    const formatBytes = (bytes: number) => {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${['Bytes', 'KB', 'MB', 'GB'][i]}`;
    };

    const formatHour = (hour: number) => {
        const h = hour % 12 || 12;
        const ampm = hour < 12 ? 'AM' : 'PM';
        return `${h}:00 ${ampm}`;
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
                        {schedule?.mode === 'smart' ? 'AI-optimized scheduling active' : 'Automated weekly backups active'}
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 relative z-10">

                    {/* Manual Backup Trigger */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-3xl p-8 flex flex-col justify-between">
                        <div>
                            <div className="w-16 h-16 bg-emerald-500/10 rounded-2xl flex items-center justify-center text-emerald-400 mb-6 border border-emerald-500/20">
                                <Database size={32} />
                            </div>
                            <h3 className="text-xl font-bold text-slate-200 mb-2">Manual Snapshot</h3>
                            <p className="text-slate-400 text-sm leading-relaxed mb-8">
                                Triggers an immediate zero-downtime hot backup of the full AetherFlow SQLite database.
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

                    {/* Smart Schedule Card */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-3xl p-8 flex flex-col justify-between">
                        <div>
                            <div className="w-16 h-16 bg-purple-500/10 rounded-2xl flex items-center justify-center text-purple-400 mb-6 border border-purple-500/20">
                                <BrainCircuit size={32} />
                            </div>
                            <h3 className="text-xl font-bold text-slate-200 mb-2">Smart Schedule</h3>
                            <p className="text-slate-400 text-sm leading-relaxed mb-4">
                                AI analyzes 30-day I/O patterns to find the optimal low-traffic backup window automatically.
                            </p>

                            {schedule?.optimal_window && (
                                <div className="space-y-3 mb-4">
                                    <div className="bg-purple-500/10 border border-purple-500/20 rounded-xl p-4">
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-[10px] uppercase tracking-wider text-purple-400 font-bold">Optimal Window</span>
                                            <span className="text-xs text-purple-300 font-bold">{(schedule.optimal_window.confidence * 100).toFixed(0)}% confidence</span>
                                        </div>
                                        <p className="text-2xl font-bold text-slate-200">
                                            {formatHour(schedule.optimal_window.optimal_hour)} – {formatHour(schedule.optimal_window.optimal_hour + Math.ceil(schedule.optimal_window.duration_mins / 60))} {schedule.optimal_window.timezone}
                                        </p>
                                        <p className="text-xs text-slate-400 mt-2 leading-relaxed">{schedule.optimal_window.reasoning}</p>
                                    </div>
                                </div>
                            )}
                        </div>

                        <button
                            onClick={toggleSmartSchedule}
                            disabled={isTogglingSchedule}
                            className={`w-full py-4 px-6 rounded-xl font-bold text-white shadow-xl transition-all flex items-center justify-center gap-3 ${schedule?.mode === 'smart'
                                ? 'bg-purple-600 hover:bg-purple-500 shadow-purple-500/20'
                                : 'bg-slate-700 hover:bg-slate-600 shadow-none'
                                }`}
                        >
                            {isTogglingSchedule ? (
                                <Loader2 size={20} className="animate-spin" />
                            ) : schedule?.mode === 'smart' ? (
                                <><ToggleRight size={20} /> Smart Scheduling ON</>
                            ) : (
                                <><ToggleLeft size={20} /> Enable Smart Scheduling</>
                            )}
                        </button>
                    </div>

                    {/* Status Console & Previous Backups */}
                    <div className="bg-slate-900 border border-white/5 rounded-3xl p-8 flex flex-col h-[500px]">
                        <h3 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-6 flex justify-between items-center">
                            <span className="flex items-center gap-2"><Clock size={16} /> Archive Snapshots</span>
                            <span className="text-xs bg-slate-800 px-2 py-1 rounded-md">{backups.length} Total</span>
                        </h3>

                        {/* Recent Status (if acting) */}
                        {backupState.status !== 'idle' && (
                            <div className={`mb-6 p-4 rounded-xl border ${backupState.status === 'success' ? 'bg-emerald-500/10 border-emerald-500/20' : backupState.status === 'error' ? 'bg-red-500/10 border-red-500/20' : 'bg-slate-800/50 border-white/10'} flex items-center gap-4`}>
                                {backupState.status === 'running' && <div className="w-6 h-6 border-2 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin"></div>}
                                {backupState.status === 'success' && <CheckCircle2 size={24} className="text-emerald-400" />}
                                {backupState.status === 'error' && <div className="text-red-400 font-bold text-xl">!</div>}

                                <div>
                                    <h4 className={`font-bold text-sm ${backupState.status === 'error' ? 'text-red-400' : 'text-slate-200'}`}>
                                        {backupState.status === 'running' ? 'Snapshotting...' : backupState.status === 'error' ? 'Operation Failed' : 'Backup Successful'}
                                    </h4>
                                    <p className="text-xs text-slate-400">{backupState.message}</p>
                                </div>
                            </div>
                        )}

                        <div className="flex-1 overflow-y-auto pr-2 space-y-3 custom-scrollbar">
                            {isLoadingBackups ? (
                                <div className="text-center text-slate-500 py-10">
                                    <div className="w-8 h-8 border-2 border-slate-500/30 border-t-slate-500 rounded-full animate-spin mx-auto mb-4"></div>
                                    <p>Loading archives...</p>
                                </div>
                            ) : backups.length === 0 ? (
                                <div className="text-center text-slate-500 py-10">
                                    <Archive size={48} className="mx-auto mb-4 opacity-50 text-slate-600" />
                                    <p>No snapshots found.</p>
                                </div>
                            ) : (
                                backups.map((bk) => (
                                    <div key={bk.filename} className="bg-slate-800/50 hover:bg-slate-800 border border-white/5 hover:border-white/10 rounded-xl p-4 flex items-center justify-between transition-colors group">
                                        <div className="flex items-center gap-4">
                                            <div className="w-10 h-10 bg-slate-900 rounded-lg flex items-center justify-center text-slate-400 border border-white/5">
                                                <Database size={18} />
                                            </div>
                                            <div>
                                                <h4 className="text-slate-200 font-mono text-xs mb-1">{bk.filename}</h4>
                                                <div className="flex gap-3 text-xs text-slate-500">
                                                    <span>{formatBytes(bk.size)}</span>
                                                    <span>&bull;</span>
                                                    <span>{new Date(bk.timestamp).toLocaleString()}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <a
                                            href={`/api/backup/download/${encodeURIComponent(bk.filename)}`}
                                            download
                                            className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center hover:bg-emerald-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                                            title="Download SQLite Archive"
                                        >
                                            <Download size={16} />
                                        </a>
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
