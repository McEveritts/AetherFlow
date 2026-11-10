import { HardDriveDownload, Archive, CheckCircle2, Clock, ShieldCheck, Database, Download, BrainCircuit, Loader2, ToggleLeft, ToggleRight } from 'lucide-react';
import { useState, useEffect, FormEvent } from 'react';
import { Modal } from '@/components/ui/Modal';
import { navigateBrowser } from '@/lib/browser-navigation';
import { apiFetch } from '@/lib/fetcher';

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
    const [downloadFilename, setDownloadFilename] = useState<string | null>(null);
    const [downloadPassword, setDownloadPassword] = useState('');
    const [downloadError, setDownloadError] = useState('');
    const [isPreparingDownload, setIsPreparingDownload] = useState(false);

    const fetchBackups = async () => {
        setIsLoadingBackups(true);
        try {
            const res = await apiFetch('/api/v1/admin/backup/list');
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
            const res = await apiFetch('/api/v1/admin/ai/backup/optimal-window');
            if (res.ok) {
                const data: ScheduleStatus = await res.json();
                setSchedule(data);
            }
        } catch {
            // Smart scheduling may not be available
        }
    };

    useEffect(() => {
        let active = true;
        apiFetch('/api/v1/admin/backup/list')
            .then(async (response) => (response.ok ? response.json() : null))
            .then((backupItems) => {
                if (!active || !Array.isArray(backupItems)) return;
                setBackups(
                    backupItems.sort(
                        (firstItem: BackupFile, secondItem: BackupFile) =>
                            new Date(secondItem.timestamp).getTime() - new Date(firstItem.timestamp).getTime()
                    )
                );
            })
            .catch((err) => {
                console.error("Failed to fetch backups", err);
            })
            .finally(() => {
                if (active) {
                    setIsLoadingBackups(false);
                }
            });
        apiFetch('/api/v1/admin/ai/backup/optimal-window')
            .then(async (response) => (response.ok ? response.json() : null))
            .then((scheduleData: ScheduleStatus | null) => {
                if (active && scheduleData) {
                    setSchedule(scheduleData);
                }
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, []);

    const handleRunBackup = async () => {
        setBackupState({ status: 'running', message: 'Initiating AetherFlow database snapshot...' });

        try {
            const res = await apiFetch('/api/v1/admin/backup/run', { method: 'POST' });
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

    const handleDownloadBackup = (filename: string) => {
        setDownloadFilename(filename);
        setDownloadPassword('');
        setDownloadError('');
    };

    const confirmDownload = async (event: FormEvent) => {
        event.preventDefault();
        if (!downloadFilename || !downloadPassword || isPreparingDownload) return;
        setIsPreparingDownload(true);
        setDownloadError('');
        const url = `/api/v1/admin/backup/download/${encodeURIComponent(downloadFilename)}`;
        try {
            const response = await apiFetch(url, {
                method: 'POST',
                headers: { 'X-Reauth-Password': downloadPassword },
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || data.error || 'Unable to authorize download.');
            // The HttpOnly proof cookie authorizes one native, streaming download.
            setDownloadPassword('');
            setDownloadFilename(null);
            navigateBrowser(url);
        } catch (error) {
            setDownloadError(error instanceof Error ? error.message : 'Unable to authorize download.');
        } finally {
            setIsPreparingDownload(false);
        }
    };

    const toggleSmartSchedule = async () => {
        if (!schedule) return;
        setIsTogglingSchedule(true);
        const newMode = schedule.mode === 'smart' ? 'manual' : 'smart';
        try {
            const res = await apiFetch('/api/v1/admin/ai/backup/schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: newMode })
            });
            if (res.ok) {
                setSchedule(prev => prev ? { ...prev, mode: newMode } : null);
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
        <div className="animate-fade-in relative z-10 w-full min-w-0 pb-10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/[0.07] relative z-10">
                <div>
                    <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                        <HardDriveDownload size={18} className="text-emerald-400" />
                        Database Snapshots &amp; Automated Archive
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">Automated and on-demand SQLite zero-downtime snapshots.</p>
                </div>
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-xl border border-emerald-500/20 self-start sm:self-auto">
                    <ShieldCheck size={14} />
                    {schedule?.mode === 'smart' ? 'Smart automation active' : 'Manual backup mode'}
                </div>
            </div>

            <div className="min-w-0 rounded-none shadow-none bg-transparent border-b border-white/[0.07] grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 divide-y xl:divide-y-0 xl:divide-x divide-white/[0.07]">

                {/* Manual Backup Trigger */}
                <div className="p-5 sm:p-6 flex flex-col justify-between min-w-0 space-y-6">
                    <div>
                        <div className="w-12 h-12 bg-emerald-500/10 rounded-xl flex items-center justify-center text-emerald-400 mb-4 border border-emerald-500/20">
                            <Database size={24} />
                        </div>
                        <h4 className="text-base font-bold text-slate-100 mb-1">Manual Snapshot</h4>
                        <p className="text-slate-400 text-xs leading-relaxed mb-6">
                            Triggers an immediate zero-downtime hot backup of the full AetherFlow SQLite database.
                        </p>
                    </div>

                    <button
                        onClick={handleRunBackup}
                        disabled={backupState.status === 'running'}
                        className={`obs-touch-target-standard obs-gpu-120hz-interactive w-full py-3.5 px-6 rounded-xl font-bold text-white shadow-xl transition-all flex items-center justify-center gap-3 min-h-[44px] ${backupState.status === 'running'
                            ? 'bg-emerald-600/50 cursor-not-allowed'
                            : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20'
                            }`}
                    >
                        {backupState.status === 'running' ? (
                            <>
                                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                Snapshotting...
                            </>
                        ) : (
                            <>
                                <Archive size={18} />
                                Generate New Archive
                            </>
                        )}
                    </button>
                </div>

                <div className="p-5 sm:p-6 flex flex-col justify-between min-w-0 space-y-6">
                    <div>
                        <div className="flex justify-between items-start mb-4">
                            <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center text-purple-400 border border-purple-500/20">
                                <BrainCircuit size={24} />
                            </div>
                            <span className="text-xs font-mono uppercase bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2.5 py-1 rounded-full">
                                FlowAI Scheduling
                            </span>
                        </div>
                        <h4 className="text-base font-bold text-slate-100 mb-1">Smart Scheduling Engine</h4>
                        <p className="text-slate-400 text-xs leading-relaxed mb-4">
                            Dynamically schedules snapshots during observed telemetry lulls to guarantee zero I/O contention.
                        </p>

                        {schedule?.optimal_window && (
                            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-slate-400">Optimal Backup Window:</span>
                                    <span className="text-purple-300 font-mono font-bold">
                                        {formatHour(schedule.optimal_window.optimal_hour)} - {formatHour(schedule.optimal_window.optimal_hour + Math.ceil(schedule.optimal_window.duration_mins / 60))}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between text-xs">
                                    <span className="text-slate-400">AI Confidence Score:</span>
                                    <span className="text-emerald-400 font-mono font-bold">
                                        {Math.round(schedule.optimal_window.confidence * 100)}%
                                    </span>
                                </div>
                                <p className="text-xs text-slate-400 italic pt-1 border-t border-white/[0.06]">
                                    &ldquo;{schedule.optimal_window.reasoning}&rdquo;
                                </p>
                                {schedule.next_backup_at && (
                                    <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between text-xs">
                                        <span className="text-slate-400">Next Scheduled Run:</span>
                                        <span className="text-slate-200 font-mono text-xs">
                                            {new Date(schedule.next_backup_at).toLocaleString()}
                                        </span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    <button
                        onClick={toggleSmartSchedule}
                        disabled={isTogglingSchedule}
                        className={`obs-touch-target-standard obs-gpu-120hz-interactive w-full py-3.5 px-6 rounded-xl font-bold text-white shadow-xl transition-all flex items-center justify-center gap-3 min-h-[44px] ${schedule?.mode === 'smart'
                            ? 'bg-purple-600 hover:bg-purple-500 shadow-purple-500/20'
                            : 'bg-slate-700 hover:bg-slate-600 shadow-none'
                            }`}
                    >
                        {isTogglingSchedule ? (
                            <Loader2 size={18} className="animate-spin" />
                        ) : schedule?.mode === 'smart' ? (
                            <><ToggleRight size={18} /> Smart Scheduling ON</>
                        ) : (
                            <><ToggleLeft size={18} /> Enable Smart Scheduling</>
                        )}
                    </button>
                </div>

                {/* Status Console & Previous Backups */}
                <div className="p-5 sm:p-6 flex flex-col min-w-0 h-[560px] md:col-span-2 xl:col-span-1">
                    <div className="text-sm font-bold text-slate-400 uppercase tracking-wider pb-3 border-b border-white/[0.07] mb-4 flex justify-between items-center">
                        <span className="flex items-center gap-2"><Clock size={16} /> Archive Snapshots</span>
                        <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded-md border border-white/5">{backups.length} Total</span>
                    </div>

                    {/* Recent Status (if acting) */}
                    {backupState.status !== 'idle' && (
                        <div className={`mb-4 p-3.5 rounded-xl border ${backupState.status === 'success' ? 'bg-emerald-500/10 border-emerald-500/20' : backupState.status === 'error' ? 'bg-rose-500/10 border-rose-500/20' : 'bg-slate-800/50 border-white/10'} flex items-center gap-3 shrink-0`}>
                            {backupState.status === 'running' && <div className="w-5 h-5 border-2 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin shrink-0"></div>}
                            {backupState.status === 'success' && <CheckCircle2 size={20} className="text-emerald-400 shrink-0" />}
                            {backupState.status === 'error' && <div className="text-rose-400 font-bold text-lg shrink-0">!</div>}

                            <div className="min-w-0">
                                <h4 className={`font-bold text-xs ${backupState.status === 'error' ? 'text-rose-400' : 'text-slate-200'}`}>
                                    {backupState.status === 'running' ? 'Snapshotting...' : backupState.status === 'error' ? 'Operation Failed' : 'Backup Successful'}
                                </h4>
                                <p className="text-xs text-slate-400 break-words">{backupState.message}</p>
                            </div>
                        </div>
                    )}

                    <div className="flex-1 overflow-y-auto divide-y divide-white/[0.07] border-y border-white/[0.07] custom-scrollbar">
                        {isLoadingBackups ? (
                            <div className="text-center text-slate-500 py-10">
                                <div className="w-8 h-8 border-2 border-slate-500/30 border-t-slate-500 rounded-full animate-spin mx-auto mb-4"></div>
                                <p className="text-xs">Loading archives...</p>
                            </div>
                        ) : backups.length === 0 ? (
                            <div className="text-center text-slate-500 py-10">
                                <Archive size={40} className="mx-auto mb-3 opacity-50 text-slate-600" />
                                <p className="text-xs">No snapshots found.</p>
                            </div>
                        ) : (
                            backups.map((bk) => (
                                <div key={bk.filename} className="py-3 px-1 hover:bg-white/[0.02] flex items-start gap-3 justify-between transition-colors group">
                                    <div className="flex items-center gap-3 min-w-0">
                                        <div className="w-9 h-9 bg-white/[0.04] rounded-lg flex items-center justify-center text-slate-400 border border-white/5 shrink-0">
                                            <Database size={16} />
                                        </div>
                                        <div className="min-w-0">
                                            <h4 className="text-slate-200 font-mono text-xs mb-0.5 break-words [overflow-wrap:anywhere]" title={bk.filename}>{bk.filename}</h4>
                                            <div className="flex flex-wrap gap-x-2 gap-y-1 text-xs text-slate-400">
                                                <span>{formatBytes(bk.size)}</span>
                                                <span>&bull;</span>
                                                <time dateTime={bk.timestamp} className="break-words">{new Date(bk.timestamp).toLocaleString()}</time>
                                            </div>
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => handleDownloadBackup(bk.filename)}
                                        className="obs-touch-target-standard obs-touch-action-reveal opacity-100 md:opacity-0 md:group-hover:opacity-100 focus:opacity-100 w-9 h-9 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center hover:bg-emerald-500 hover:text-white transition-all shrink-0 min-h-[36px] min-w-[36px]"
                                        title="Download SQLite Archive"
                                    >
                                        <Download size={15} />
                                    </button>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>

            <Modal isOpen={downloadFilename !== null} title="Download backup" role="dialog" aria-modal="true" aria-label="Download backup"
                onClose={() => { if (!isPreparingDownload) { setDownloadFilename(null); setDownloadPassword(''); setDownloadError(''); } }}>
                <form onSubmit={confirmDownload} className="space-y-4">
                    <p className="text-sm text-slate-300 break-all">Confirm your password to download {downloadFilename}.</p>
                    <label className="block text-sm">
                        Current password
                        <input type="password" autoComplete="current-password" autoFocus required value={downloadPassword}
                            onChange={event => setDownloadPassword(event.target.value)} disabled={isPreparingDownload}
                            className="mt-2 block w-full rounded-lg bg-slate-950 border border-white/10 p-3" />
                    </label>
                    {downloadError && <p role="alert" className="text-sm text-red-400">{downloadError}</p>}
                    <button type="submit" disabled={isPreparingDownload || !downloadPassword}
                        className="obs-touch-target-standard w-full rounded-lg p-3 bg-emerald-600 disabled:opacity-50">
                        {isPreparingDownload ? 'Authorizing…' : 'Authorize download'}
                    </button>
                </form>
            </Modal>
        </div>
    );
}
