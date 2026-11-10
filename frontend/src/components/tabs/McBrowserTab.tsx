'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
    Folder,
    FolderPlus,
    FileText,
    UploadCloud,
    Download,
    Trash2,
    Edit3,
    RefreshCw,
    ChevronRight,
    ArrowUp,
    Search,
    Eye,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    Loader2,
    X,
    Link2Off,
    ShieldAlert,
    ArrowUpDown,
    HardDrive,
    FileQuestion,
    Info,
    Pause,
    Play,
    Settings,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import McBrowserWorkspace from '@/components/mcbrowser/McBrowserWorkspace';
import McBrowserMediaPreview from '@/components/mcbrowser/McBrowserMediaPreview';
import { Modal } from '@/components/ui/Modal';
import { classifyMcBrowserMediaCategory } from '@/lib/mcbrowser-media';
import { McBrowserPolicyResponse, McBrowserPolicyPermissions } from '@/lib/mcbrowser-workspace';
import {
    McBrowserEntry,
    getMcBrowserEntryTargetKind,
    McBrowserPreviewResponse,
    DEFAULT_MAX_UPLOAD_BYTES,
    MAX_PREVIEW_BYTES,
    normalizeRelativePath,
    joinRelativePath,
    validateEntryName,
    buildBreadcrumbs,
    listMcBrowserEntries,
    createMcBrowserDirectory,
    ensureMcBrowserDirectory,
    renameMcBrowserEntry,
    deleteMcBrowserEntry,
    fetchMcBrowserPreview,
    downloadMcBrowserFile,
    extractMcBrowserError,
    formatBytes,
    formatModifiedDate,
} from '@/lib/mcbrowser';
import {
    cancelMcBrowserResumable,
    uploadMcBrowserResumable,
} from '@/lib/mcbrowser-resumable';
import {
    McBrowserUploadQueue,
    UploadQueueItem,
    scanTransferItems,
    DEFAULT_UPLOAD_CONCURRENCY,
    summarizeMcBrowserUploadQueue,
    formatMcBrowserUploadEta,
} from '@/lib/mcbrowser-uploads';

type SortField = 'name' | 'size' | 'modified' | 'kind';
type SortDirection = 'asc' | 'desc';

const DENIED_PERMISSIONS: McBrowserPolicyPermissions = {
    read: false,
    create: false,
    rename: false,
    modify: false,
    delete: false,
    share: false,
    download: false,
    execute: false,
};

export default function McBrowserTab({ isActive = true }: { isActive?: boolean }) {
    const { user, isAuthenticated } = useAuth();
    const { addToast } = useToast();
    const setActiveTab = useSystemStore((s) => s.setActiveTab);
    const setActiveSettingsTab = useSystemStore((s) => s.setActiveSettingsTab);
    const [hasActivated, setHasActivated] = useState<boolean>(Boolean(isActive));
    const [sessionEpoch, setSessionEpoch] = useState<number>(0);
    const [currentPath, setCurrentPath] = useState<string>('');
    const [entries, setEntries] = useState<McBrowserEntry[]>([]);
    const [permissions, setPermissions] = useState(DENIED_PERMISSIONS);
    const [mediaTarget, setMediaTarget] = useState<McBrowserEntry | null>(null);
    const handlePolicyChange = useCallback((policy: McBrowserPolicyResponse | null) => {
        setPermissions(policy?.permissions ?? DENIED_PERMISSIONS);
    }, []);
    const [maxUploadBytes, setMaxUploadBytes] = useState<number>(DEFAULT_MAX_UPLOAD_BYTES);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [selectedPath, setSelectedPath] = useState<string | null>(null);
    const [filterQuery, setFilterQuery] = useState<string>('');
    const [sortField, setSortField] = useState<SortField>('name');
    const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
    const [isMutating, setIsMutating] = useState<boolean>(false);
    const [downloadingPath, setDownloadingPath] = useState<string | null>(null);
    const [isDragging, setIsDragging] = useState<boolean>(false);
    const [uploadQueue, setUploadQueue] = useState<UploadQueueItem[]>([]);
    const isUploadingBatch = uploadQueue.some(
        (item) => item.status === 'pending' || item.status === 'uploading' || item.status === 'pausing' || item.status === 'cancelling'
    );
    const hasPausedUploads = uploadQueue.some((item) => item.status === 'paused' || item.status === 'pausing');

    const [mkdirOpen, setMkdirOpen] = useState<boolean>(false);
    const [mkdirName, setMkdirName] = useState<string>('');
    const [mkdirError, setMkdirError] = useState<string | null>(null);

    const [renameTarget, setRenameTarget] = useState<McBrowserEntry | null>(null);
    const [renameValue, setRenameValue] = useState<string>('');
    const [renameError, setRenameError] = useState<string | null>(null);

    const [deleteTarget, setDeleteTarget] = useState<McBrowserEntry | null>(null);
    const [deleteError, setDeleteError] = useState<string | null>(null);
    const [previewTarget, setPreviewTarget] = useState<McBrowserEntry | null>(null);
    const [previewData, setPreviewData] = useState<McBrowserPreviewResponse | null>(null);
    const [previewLoading, setPreviewLoading] = useState<boolean>(false);
    const [previewError, setPreviewError] = useState<string | null>(null);

    const mkdirInputRef = useRef<HTMLInputElement | null>(null);
    const mkdirOpenerRef = useRef<HTMLElement | null>(null);
    const renameInputRef = useRef<HTMLInputElement | null>(null);
    const renameOpenerRef = useRef<HTMLElement | null>(null);
    const deleteCancelRef = useRef<HTMLButtonElement | null>(null);
    const deleteOpenerRef = useRef<HTMLElement | null>(null);
    const previewDownloadRef = useRef<HTMLButtonElement | null>(null);
    const previewOpenerRef = useRef<HTMLElement | null>(null);

    const requestSeqRef = useRef<number>(0);
    const activeAbortRef = useRef<AbortController | null>(null);
    const previewSeqRef = useRef<number>(0);
    const previewAbortRef = useRef<AbortController | null>(null);
    const fileInputRef = useRef<HTMLInputElement | null>(null);
    const folderInputRef = useRef<HTMLInputElement | null>(null);
    const uploadManagerRef = useRef<McBrowserUploadQueue | null>(null);
    const currentPathRef = useRef('');
    const maxUploadBytesRef = useRef(DEFAULT_MAX_UPLOAD_BYTES);
    const hasLoadedRef = useRef(false);
    const isActiveRef = useRef<boolean>(Boolean(isActive));

    const sessionIdentity = useMemo(
        () => (user?.id !== undefined && user?.id !== null ? `user:${user.id}` : isAuthenticated ? 'auth' : 'anon'),
        [user?.id, isAuthenticated]
    );
    const prevSessionIdentityRef = useRef<string>(sessionIdentity);

    const anyBusy = isMutating || isUploadingBatch;

    if (isActive && !hasActivated) {
        setHasActivated(true);
    }

    useEffect(() => {
        isActiveRef.current = Boolean(isActive);
        if (!isActive) {
            setMkdirOpen(false);
            setRenameTarget(null);
            setDeleteTarget(null);
            setPreviewTarget(null);
        }
    }, [isActive]);

    const fetchDirectory = useCallback(
        async (pathToLoad: string, options?: { background?: boolean }) => {
            const normalizedTarget = normalizeRelativePath(pathToLoad);
            const seq = ++requestSeqRef.current;

            if (activeAbortRef.current) {
                activeAbortRef.current.abort();
            }
            const controller = new AbortController();
            activeAbortRef.current = controller;

            if (options?.background) {
                setIsRefreshing(true);
            } else {
                setIsLoading(true);
                setLoadError(null);
            }

            try {
                const res = await listMcBrowserEntries(normalizedTarget, controller.signal);
                if (seq !== requestSeqRef.current) {
                    return;
                }
                const resolvedPath = normalizeRelativePath(res.path ?? normalizedTarget);
                setCurrentPath(resolvedPath);
                setEntries(Array.isArray(res.entries) ? res.entries : []);
                if (typeof res.max_upload_bytes === 'number' && res.max_upload_bytes > 0) {
                    setMaxUploadBytes(res.max_upload_bytes);
                }
                setLoadError(null);
                setSelectedPath((prev) => {
                    if (!prev) return null;
                    const stillExists = (res.entries || []).some((e) => e.path === prev);
                    return stillExists ? prev : null;
                });
            } catch (err) {
                if (seq !== requestSeqRef.current) {
                    return;
                }
                if (err instanceof Error && err.name === 'AbortError') {
                    return;
                }
                const msg = extractMcBrowserError(err, 'Failed to load directory contents.');
                setLoadError(msg);
            } finally {
                if (seq === requestSeqRef.current) {
                    setIsLoading(false);
                    setIsRefreshing(false);
                }
            }
        },
        []
    );

    const resetSessionWorkspaceState = useCallback((bumpEpoch = true) => {
        requestSeqRef.current += 1;
        previewSeqRef.current += 1;
        if (activeAbortRef.current) {
            activeAbortRef.current.abort();
            activeAbortRef.current = null;
        }
        if (previewAbortRef.current) {
            previewAbortRef.current.abort();
            previewAbortRef.current = null;
        }
        if (uploadManagerRef.current) {
            uploadManagerRef.current.dispose();
            uploadManagerRef.current = null;
        }
        hasLoadedRef.current = false;
        currentPathRef.current = '';
        setCurrentPath('');
        setEntries([]);
        setPermissions(DENIED_PERMISSIONS);
        setMediaTarget(null);
        setSelectedPath(null);
        setFilterQuery('');
        setLoadError(null);
        setUploadQueue([]);
        setMkdirOpen(false);
        setRenameTarget(null);
        setDeleteTarget(null);
        setPreviewTarget(null);
        setPreviewData(null);
        setPreviewError(null);
        setPreviewLoading(false);
        if (bumpEpoch) {
            setSessionEpoch((prev) => prev + 1);
        }
    }, []);

    useEffect(() => {
        if (prevSessionIdentityRef.current !== sessionIdentity) {
            prevSessionIdentityRef.current = sessionIdentity;
            resetSessionWorkspaceState(false);
        }
    }, [resetSessionWorkspaceState, sessionIdentity]);

    useEffect(() => {
        const handleSessionExpired = () => {
            resetSessionWorkspaceState(true);
        };
        const handleStorageChange = (event: StorageEvent) => {
            if (event.key === 'af_logout_sync' || event.key === 'af_login_sync') {
                resetSessionWorkspaceState(true);
            }
        };
        window.addEventListener('af:session-expired', handleSessionExpired);
        window.addEventListener('storage', handleStorageChange);
        return () => {
            window.removeEventListener('af:session-expired', handleSessionExpired);
            window.removeEventListener('storage', handleStorageChange);
        };
    }, [resetSessionWorkspaceState]);

    useEffect(() => {
        if (isActive && !hasLoadedRef.current) {
            hasLoadedRef.current = true;
            void fetchDirectory('');
        }
    }, [fetchDirectory, isActive, sessionEpoch, sessionIdentity]);

    useEffect(() => {
        return () => {
            hasLoadedRef.current = false;
            if (activeAbortRef.current) {
                activeAbortRef.current.abort();
            }
            if (previewAbortRef.current) {
                previewAbortRef.current.abort();
            }
        };
    }, []);

    useEffect(() => {
        currentPathRef.current = currentPath;
        maxUploadBytesRef.current = maxUploadBytes;
    }, [currentPath, maxUploadBytes]);

    useEffect(() => {
        const manager = new McBrowserUploadQueue({
            concurrency: DEFAULT_UPLOAD_CONCURRENCY,
            upload: (path, file, signal, onProgress, conflict) =>
                uploadMcBrowserResumable(path, file, { signal, onProgress, conflict }),
            cancelSession: (path, file, signal, conflict) =>
                cancelMcBrowserResumable(path, file, { signal, conflict }),
            ensureDirectory: ensureMcBrowserDirectory,
            onChange: setUploadQueue,
            onIdle: () => {
                const results = manager.snapshot();
                if (results.length === 0) {
                    return;
                }
                const successful = results.filter((item) => item.status === 'success' && !item.skipped).length;
                const skipped = results.filter((item) => item.skipped).length;
                const failed = results.filter((item) => item.status === 'error').length;
                const uncertain = results.filter((item) => item.status === 'uncertain').length;
                addToast(
                    `Upload queue finished: ${successful} uploaded; ${skipped} skipped; ${failed} failed; ${uncertain} need destination checks.`,
                    failed || uncertain ? 'info' : 'success'
                );
                void fetchDirectory(currentPathRef.current, { background: true });
            },
        });
        uploadManagerRef.current = manager;
        return () => {
            manager.dispose();
            uploadManagerRef.current = null;
        };
    }, [addToast, fetchDirectory, sessionEpoch, sessionIdentity]);

    useEffect(() => {
        if (!isUploadingBatch) return;
        const warnBeforeLeaving = (event: BeforeUnloadEvent) => {
            event.preventDefault();
            event.returnValue = '';
        };
        window.addEventListener('beforeunload', warnBeforeLeaving);
        return () => window.removeEventListener('beforeunload', warnBeforeLeaving);
    }, [isUploadingBatch]);

    const navigateTo = useCallback(
        (targetRelativePath: string) => {
            let normalized = '';
            try {
                normalized = normalizeRelativePath(targetRelativePath);
            } catch (err) {
                addToast(extractMcBrowserError(err, 'Invalid folder path.'), 'error');
                return;
            }
            if (previewAbortRef.current) {
                previewAbortRef.current.abort();
            }
            setPreviewTarget(null);
            setPreviewData(null);
            setPreviewError(null);
            setSelectedPath(null);
            setCurrentPath(normalized);
            void fetchDirectory(normalized);
        },
        [addToast, fetchDirectory]
    );

    const handleWorkspaceRefresh = useCallback(() => {
        void fetchDirectory(currentPathRef.current, { background: true });
    }, [fetchDirectory]);

    const handleNavigateUp = useCallback(() => {
        if (!currentPath) return;
        const parts = currentPath.split('/').filter(Boolean);
        parts.pop();
        navigateTo(parts.join('/'));
    }, [currentPath, navigateTo]);

    const breadcrumbs = useMemo(() => buildBreadcrumbs(currentPath), [currentPath]);

    const selectedEntry = useMemo(
        () => entries.find((item) => item.path === selectedPath) ?? null,
        [entries, selectedPath]
    );

    const filteredAndSortedEntries = useMemo(() => {
        const q = filterQuery.trim().toLowerCase();
        const filtered = q
            ? entries.filter((item) => item.name.toLowerCase().includes(q))
            : [...entries];

        filtered.sort((a, b) => {
            if (sortField !== 'kind') {
                const aIsDir = getMcBrowserEntryTargetKind(a) === 'directory' ? 0 : 1;
                const bIsDir = getMcBrowserEntryTargetKind(b) === 'directory' ? 0 : 1;
                if (aIsDir !== bIsDir) {
                    return aIsDir - bIsDir;
                }
            }

            let cmp = 0;
            if (sortField === 'name') {
                cmp = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
            } else if (sortField === 'size') {
                cmp = (a.size || 0) - (b.size || 0);
            } else if (sortField === 'modified') {
                const aTime = a.modified ? Date.parse(a.modified) || 0 : 0;
                const bTime = b.modified ? Date.parse(b.modified) || 0 : 0;
                cmp = aTime - bTime;
            } else if (sortField === 'kind') {
                cmp = a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name);
            }

            return sortDirection === 'asc' ? cmp : -cmp;
        });

        return filtered;
    }, [entries, filterQuery, sortField, sortDirection]);

    const toggleSort = (field: SortField) => {
        if (sortField === field) {
            setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
        } else {
            setSortField(field);
            setSortDirection('asc');
        }
    };

    const openMkdirDialog = (openerElement?: HTMLElement | null) => {
        mkdirOpenerRef.current =
            openerElement ??
            (document.activeElement instanceof HTMLElement ? document.activeElement : null);
        setMkdirName('');
        setMkdirError(null);
        setMkdirOpen(true);
    };

    const handleCreateDirectory = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!permissions.create) return;
        const validationErr = validateEntryName(mkdirName);
        if (validationErr) {
            setMkdirError(validationErr);
            return;
        }

        let targetPath = '';
        try {
            targetPath = joinRelativePath(currentPath, mkdirName);
        } catch (err) {
            setMkdirError(extractMcBrowserError(err, 'Invalid folder name.'));
            return;
        }

        setIsMutating(true);
        setMkdirError(null);
        try {
            await createMcBrowserDirectory(targetPath);
            addToast(`Created folder "${mkdirName.trim()}"`, 'success');
            setMkdirOpen(false);
            setMkdirName('');
            await fetchDirectory(currentPath, { background: true });
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to create folder.');
            setMkdirError(msg);
            addToast(msg, 'error');
        } finally {
            setIsMutating(false);
        }
    };

    const openRenameDialog = (
        entry: McBrowserEntry,
        openerElement?: HTMLElement | null
    ) => {
        renameOpenerRef.current =
            openerElement ??
            (document.activeElement instanceof HTMLElement ? document.activeElement : null);
        if (!permissions.rename) return;
        if (entry.kind === 'other') {
            addToast(`Cannot rename unsupported entry type (${entry.kind}).`, 'info');
            return;
        }
        setRenameTarget(entry);
        setRenameValue(entry.name);
        setRenameError(null);
    };

    const handleRenameSubmit = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!permissions.rename) return;
        if (!renameTarget) return;

        const trimmed = renameValue;
        const validationErr = validateEntryName(trimmed);
        if (validationErr) {
            setRenameError(validationErr);
            return;
        }
        if (trimmed === renameTarget.name) {
            setRenameError('New name must be different from the current name.');
            return;
        }

        const parentSegments = normalizeRelativePath(renameTarget.path).split('/');
        parentSegments.pop();
        const parentDir = parentSegments.join('/');

        let destinationPath = '';
        try {
            destinationPath = joinRelativePath(parentDir, trimmed);
        } catch (err) {
            setRenameError(extractMcBrowserError(err, 'Invalid target name.'));
            return;
        }

        setIsMutating(true);
        setRenameError(null);
        try {
            await renameMcBrowserEntry(renameTarget.path, destinationPath);
            addToast(`Renamed "${renameTarget.name}" to "${trimmed}"`, 'success');
            if (selectedPath === renameTarget.path) {
                setSelectedPath(destinationPath);
            }
            setRenameTarget(null);
            await fetchDirectory(currentPath, { background: true });
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to rename item.');
            setRenameError(msg);
            addToast(msg, 'error');
        } finally {
            setIsMutating(false);
        }
    };

    const openDeleteDialog = (
        entry: McBrowserEntry,
        openerElement?: HTMLElement | null
    ) => {
        deleteOpenerRef.current =
            openerElement ??
            (document.activeElement instanceof HTMLElement ? document.activeElement : null);
        if (!permissions.delete) return;
        if (entry.kind === 'other') {
            addToast(`Deleting ${entry.kind} entries is not supported.`, 'info');
            return;
        }
        setDeleteTarget(entry);
        setDeleteError(null);
    };

    const handleDeleteConfirm = async () => {
        if (!permissions.delete) return;
        if (!deleteTarget) return;
        setIsMutating(true);
        setDeleteError(null);
        try {
            await deleteMcBrowserEntry(deleteTarget.path);
            addToast(`Deleted "${deleteTarget.name}"`, 'success');
            if (selectedPath === deleteTarget.path) {
                setSelectedPath(null);
            }
            if (previewTarget?.path === deleteTarget.path) {
                setPreviewTarget(null);
                setPreviewData(null);
            }
            setDeleteTarget(null);
            await fetchDirectory(currentPath, { background: true });
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to delete item.');
            setDeleteError(msg);
            addToast(msg, 'error');
        } finally {
            setIsMutating(false);
        }
    };

    const handleFilesSelected = (
        fileList: FileList | File[],
        emptyDirectories: string[] = []
    ) => {
        if (!permissions.create) return;
        try {
            uploadManagerRef.current?.enqueue(
                Array.from(fileList),
                currentPathRef.current,
                maxUploadBytesRef.current,
                emptyDirectories
            );
        } catch (error) {
            addToast(extractMcBrowserError(error, 'Unable to add files to upload queue.'), 'error');
        }
    };

    const handleDropUpload = async (dataTransfer: DataTransfer | null | undefined) => {
        try {
            const { files, emptyDirectories } = await scanTransferItems(dataTransfer);
            if (files.length === 0 && emptyDirectories.length === 0) {
                return;
            }
            handleFilesSelected(files, emptyDirectories);
        } catch (error) {
            addToast(
                extractMcBrowserError(error, 'Unable to read dropped files or folders.'),
                'error'
            );
        }
    };

    const handleDownload = async (entry: McBrowserEntry) => {
        if (!permissions.download) return;
        if (getMcBrowserEntryTargetKind(entry) !== 'file') {
            addToast('Only regular files can be downloaded.', 'info');
            return;
        }
        setDownloadingPath(entry.path);
        try {
            await downloadMcBrowserFile(entry.path, entry.name);
            addToast(`Downloaded "${entry.name}"`, 'success');
        } catch (err) {
            addToast(extractMcBrowserError(err, `Failed to download "${entry.name}".`), 'error');
        } finally {
            setDownloadingPath(null);
        }
    };

    const handleOpenPreview = async (
        entry: McBrowserEntry,
        openerElement?: HTMLElement | null
    ) => {
        previewOpenerRef.current =
            openerElement ??
            (document.activeElement instanceof HTMLElement ? document.activeElement : null);
        if (!permissions.read) return;
        if (getMcBrowserEntryTargetKind(entry) !== 'file') {
            addToast('Only regular files can be previewed.', 'info');
            return;
        }

        if (classifyMcBrowserMediaCategory(entry.name) !== 'unsupported') {
            setMediaTarget(entry);
            return;
        }

        const seq = ++previewSeqRef.current;
        if (previewAbortRef.current) {
            previewAbortRef.current.abort();
        }
        const controller = new AbortController();
        previewAbortRef.current = controller;

        setPreviewTarget(entry);
        setPreviewData(null);
        setPreviewError(null);
        setPreviewLoading(true);

        try {
            const res = await fetchMcBrowserPreview(entry.path, controller.signal);
            if (seq !== previewSeqRef.current) return;
            setPreviewData(res);
        } catch (err) {
            if (seq !== previewSeqRef.current) return;
            if (err instanceof Error && err.name === 'AbortError') return;
            setPreviewError(extractMcBrowserError(err, 'Unable to preview file as UTF-8 text.'));
        } finally {
            if (seq === previewSeqRef.current) {
                setPreviewLoading(false);
            }
        }
    };

    const closePreviewDialog = () => {
        if (previewAbortRef.current) {
            previewAbortRef.current.abort();
        }
        setPreviewTarget(null);
        setPreviewData(null);
        setPreviewError(null);
        setPreviewLoading(false);
    };

    const handleEntryActivate = (entry: McBrowserEntry) => {
        if (getMcBrowserEntryTargetKind(entry) === 'directory') {
            navigateTo(entry.path);
        } else if (getMcBrowserEntryTargetKind(entry) === 'file') {
            void handleOpenPreview(entry);
        }
    };

    const dirCount = useMemo(
        () => entries.filter((entry) => getMcBrowserEntryTargetKind(entry) === 'directory').length,
        [entries]
    );
    const fileCount = useMemo(
        () => entries.filter((entry) => getMcBrowserEntryTargetKind(entry) === 'file').length,
        [entries]
    );
    const unsupportedCount = useMemo(
        () => entries.filter((e) => e.kind === 'other').length,
        [entries]
    );

    const uploadSummary = useMemo(() => summarizeMcBrowserUploadQueue(uploadQueue), [uploadQueue]);
    const confirmedQueueBytes = uploadSummary.confirmedBytes;
    const uploadEta = formatMcBrowserUploadEta(uploadSummary.etaSeconds);

    return (
        <div
            className="space-y-6 animate-fade-in relative z-10 w-full min-w-0"
            role="region"
            aria-label="McBrowser workspace"
            onDragOver={(e) => {
                e.preventDefault();
                if (permissions.create && !isMutating && !isLoading) setIsDragging(true);
            }}
            onDragLeave={(e) => {
                if (e.currentTarget === e.target) {
                    setIsDragging(false);
                }
            }}
            onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (!permissions.create || isMutating || isLoading) return;
                void handleDropUpload(e.dataTransfer);
            }}
        >
            <input
                ref={fileInputRef}
                type="file"
                multiple
                aria-label="Upload files"
                className="hidden"
                disabled={!permissions.create || isMutating || isLoading}
                onChange={(e) => {
                    if (e.target.files && e.target.files.length > 0) {
                        handleFilesSelected(e.target.files);
                        e.target.value = '';
                    }
                }}
            />
            <input
                ref={folderInputRef}
                type="file"
                multiple
                {...{ webkitdirectory: '', directory: '' }}
                aria-label="Upload folder"
                className="hidden"
                disabled={!permissions.create || isMutating || isLoading}
                onChange={(event) => {
                    if (event.target.files?.length) handleFilesSelected(event.target.files);
                    event.target.value = '';
                }}
            />
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
                <div className="flex items-center gap-3.5">
                    <div className="h-11 w-11 rounded-2xl flex items-center justify-center border bg-indigo-500/15 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.2)] text-indigo-400">
                        <Folder size={22} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5 flex-wrap">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">
                                McBrowser
                            </h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Scoped Workspace
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                            Authenticated file manager scoped to <span className="text-slate-200 font-semibold">My files</span> · Resumable uploads ({formatBytes(maxUploadBytes)} max per file) · Confirmed recursive deletion
                        </p>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        onClick={(event) => openMkdirDialog(event.currentTarget)}
                        disabled={!permissions.create || anyBusy || isLoading}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-200 hover:bg-white/[0.08] hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    >
                        <FolderPlus size={15} className="text-indigo-400" />
                        <span>New Folder</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={!permissions.create || isMutating || isLoading}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-500/20 border border-indigo-500/40 text-indigo-200 hover:bg-indigo-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-indigo-500/10"
                    >
                        {isUploadingBatch ? (
                            <Loader2 size={15} className="animate-spin text-indigo-300" />
                        ) : (
                            <UploadCloud size={15} className="text-indigo-300" />
                        )}
                        <span>{isUploadingBatch ? 'Add Files' : 'Upload Files'}</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => folderInputRef.current?.click()}
                        disabled={!permissions.create || isMutating || isLoading}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] hover:text-white border border-indigo-500/40 text-indigo-200 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    >
                        <Folder size={15} className="text-indigo-300" />
                        <span>Upload Folder</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => fetchDirectory(currentPath, { background: true })}
                        disabled={isLoading || isRefreshing || anyBusy}
                        aria-label="Refresh directory"
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    >
                        <RefreshCw
                            size={15}
                            className={isRefreshing ? 'animate-spin text-indigo-400' : 'text-slate-400'}
                        />
                        <span>Refresh</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => {
                            setActiveSettingsTab('mcbrowser');
                            setActiveTab('settings');
                        }}
                        aria-label="McBrowser Settings"
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                    >
                        <Settings size={15} className="text-indigo-400" />
                        <span>Settings</span>
                    </button>
                </div>
            </div>
            <details className="obs-canvas-section group">
                <summary className="obs-touch-target-standard min-h-[44px] cursor-pointer px-1 py-3 text-sm font-semibold text-slate-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400">
                    Workspace scope &amp; safety
                    <span className="ml-3 text-xs font-normal text-slate-400">{dirCount} folders · {fileCount} files</span>
                </summary>
            <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-white/[0.07] border-t border-white/[0.07]">
                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Current Scope</p>
                        <p className="text-sm font-bold text-slate-100 mt-1 truncate max-w-[240px]" title={currentPath ? `My files/${currentPath}` : 'My files'}>
                            {currentPath ? `My files / ${currentPath}` : 'My files'}
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5">
                            {dirCount} folder{dirCount === 1 ? '' : 's'} · {fileCount} file{fileCount === 1 ? '' : 's'}
                            {unsupportedCount > 0 ? ` · ${unsupportedCount} unsupported` : ''}
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                        <HardDrive size={19} />
                    </div>
                </div>

                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Upload Guardrails</p>
                        <p className="text-sm font-bold text-slate-100 mt-1">
                            Max {formatBytes(maxUploadBytes)} / file
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5">
                            Resumable TUS · Existing files require an explicit conflict choice
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                        <UploadCloud size={19} />
                    </div>
                </div>

                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Safety Rules</p>
                        <p className="text-sm font-bold text-slate-100 mt-1">
                            Scoped Paths &amp; UTF-8 Preview
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5">
                            Recursive deletion requires confirmation · Text preview up to {formatBytes(MAX_PREVIEW_BYTES, 0)}
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
                        <ShieldAlert size={19} />
                    </div>
                </div>
            </div>
            </details>
            {uploadQueue.length > 0 && (
                <div
                    role="region"
                    aria-label="Upload progress"
                    className="obs-canvas-section py-4 space-y-3"
                >
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            {isUploadingBatch ? (
                                <Loader2 size={16} className="animate-spin text-indigo-400" />
                            ) : (
                                <UploadCloud size={16} className="text-indigo-400" />
                            )}
                            <span className="text-xs font-bold uppercase tracking-wider text-slate-200">
                                {isUploadingBatch
                                    ? `Batch uploads · up to ${DEFAULT_UPLOAD_CONCURRENCY} requests in flight`
                                    : hasPausedUploads
                                    ? 'Batch uploads paused'
                                    : 'Upload batch complete'}
                            </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                            {isUploadingBatch && (
                                <button
                                    type="button"
                                    onClick={() => uploadManagerRef.current?.pause()}
                                    className="text-indigo-300 px-2 py-1"
                                >
                                    Pause all uploads
                                </button>
                            )}
                            {hasPausedUploads && (
                                <button
                                    type="button"
                                    onClick={() => uploadManagerRef.current?.resume()}
                                    className="text-emerald-300 px-2 py-1"
                                >
                                    Resume paused uploads
                                </button>
                            )}
                            {(isUploadingBatch || hasPausedUploads) && (
                                <button
                                    type="button"
                                    onClick={() => uploadManagerRef.current?.cancel()}
                                    className="text-amber-300 px-2 py-1"
                                >
                                    Cancel all uploads
                                </button>
                            )}
                            {uploadQueue.some(
                                (item) => item.status === 'error' || item.status === 'cancelled'
                            ) && (
                                <button
                                    type="button"
                                    onClick={() => uploadManagerRef.current?.retryFailed()}
                                    className="text-indigo-300 px-2 py-1"
                                >
                                    Retry failed / queued cancellations
                                </button>
                            )}
                            <button
                                type="button"
                                onClick={() => uploadManagerRef.current?.clearCompleted()}
                                aria-label="Clear finished uploads"
                                className="text-slate-400 px-2 py-1"
                            >
                                Clear finished
                            </button>
                        </div>
                    </div>

                    <p className="text-xs text-slate-400" aria-live="polite">
                        {uploadQueue.filter((item) => item.status === 'success' && item.kind !== 'directory' && !item.skipped).length} files confirmed uploaded · {uploadQueue.filter((item) => item.skipped).length} skipped · {formatBytes(confirmedQueueBytes)} / {formatBytes(uploadSummary.totalBytes)} file bytes confirmed.
                        Queue limits: 1,000 files / 16 GiB; {formatBytes(maxUploadBytes)} per file. Batches are not atomic. Drag-and-drop preserves empty folders; browser folder pickers only emit files.
                    </p>
                    {uploadSummary.totalBytes > 0 && (
                        <div role="progressbar" aria-label="Confirmed upload bytes" aria-valuemin={0} aria-valuemax={uploadSummary.totalBytes} aria-valuenow={confirmedQueueBytes} className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div className="h-full bg-indigo-400 transition-[width]" style={{ width: `${Math.min(100, confirmedQueueBytes / uploadSummary.totalBytes * 100)}%` }} />
                        </div>
                    )}
                    {isUploadingBatch && uploadSummary.speedBytesPerSecond > 0 && (
                        <p className="text-xs font-mono text-indigo-200" aria-label="Upload transfer estimate">
                            {formatBytes(uploadSummary.speedBytesPerSecond)}/s{uploadEta ? ` · ETA ${uploadEta}` : ''}
                        </p>
                    )}
                    {uploadQueue.some((item) => item.status === 'uncertain') && (
                        <p role="alert" className="text-xs text-amber-300">
                            Interrupted requests may have completed on the server. Refresh and check the destination before selecting those files again; uncertain uploads are not retried automatically.
                        </p>
                    )}
                    <div className="divide-y divide-white/[0.06] border-t border-white/[0.06] max-h-44 overflow-y-auto pr-1">
                        {uploadQueue.map((item) => (
                            <div
                                key={item.id}
                                className="flex items-center justify-between gap-3 px-2 py-2 text-xs"
                            >
                                <div className="flex items-center gap-2.5 min-w-0">
                                    {item.status === 'pending' && (
                                        <span className="w-2 h-2 rounded-full bg-slate-500 shrink-0" />
                                    )}
                                    {item.status === 'uploading' && (
                                        <Loader2 size={14} className="animate-spin text-indigo-400 shrink-0" />
                                    )}
                                    {item.status === 'paused' && (
                                        <Pause size={14} className="text-amber-300 shrink-0" />
                                    )}
                                    {item.status === 'success' && (
                                        <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                                    )}
                                    {item.status === 'error' && (
                                        <XCircle size={14} className="text-rose-400 shrink-0" />
                                    )}
                                    {item.status === 'success' && item.skipped && (
                                        <span className="text-slate-300">Skipped; existing file kept</span>
                                    )}
                                    {item.status === 'error' && item.conflictDetected && (
                                        <div className="flex flex-wrap gap-2" aria-label={`Resolve conflict for ${item.name}`}>
                                            <button type="button" disabled={!permissions.create} onClick={() => uploadManagerRef.current?.resolveConflict(item.id, 'skip')}>Skip existing</button>
                                            <button type="button" disabled={!permissions.modify} onClick={() => uploadManagerRef.current?.resolveConflict(item.id, 'overwrite')}>Overwrite existing</button>
                                            <button type="button" disabled={!permissions.modify} onClick={() => uploadManagerRef.current?.resolveConflict(item.id, 'resume')}>Resume existing prefix</button>
                                        </div>
                                    )}
                                    <span className="font-medium text-slate-200 truncate" title={item.targetPath}>
                                        {item.name}
                                    </span>
                                    <span className="text-slate-500 font-mono shrink-0">
                                        {item.kind === 'directory' ? (
                                            '(Empty folder)'
                                        ) : typeof item.uploadedBytes === 'number' &&
                                          item.uploadedBytes > 0 &&
                                          item.status !== 'success' ? (
                                            `(${formatBytes(item.uploadedBytes)} / ${formatBytes(item.size)}${
                                                item.speedBytesPerSecond && item.speedBytesPerSecond > 0
                                                    ? ` · ${formatBytes(item.speedBytesPerSecond)}/s`
                                                    : ''
                                            })`
                                        ) : (
                                            `(${formatBytes(item.size)})`
                                        )}
                                    </span>
                                </div>

                                <div className="shrink-0 text-right flex items-center gap-2">
                                    {item.status === 'pending' && (
                                        <span className="text-slate-400">Queued</span>
                                    )}
                                    {item.status === 'uploading' && (
                                        <span className="text-indigo-300 font-semibold">Uploading...</span>
                                    )}
                                    {item.status === 'pausing' && <span className="text-amber-200">Pausing...</span>}
                                    {item.status === 'cancelling' && <span className="text-amber-200">Confirming cancellation...</span>}
                                    {item.status === 'paused' && (
                                        <span className="text-amber-200 font-semibold">Paused</span>
                                    )}
                                    {item.status === 'success' && (
                                        <span className="text-emerald-400 font-semibold">
                                            {item.kind === 'directory' ? 'Folder created' : 'Uploaded'}
                                        </span>
                                    )}
                                    {item.status === 'cancelled' && (
                                        <span className="text-slate-400">Cancelled</span>
                                    )}
                                    {item.status === 'uncertain' && (
                                        <span className="text-amber-300">Check destination</span>
                                    )}

                                    {(item.status === 'pending' || item.status === 'uploading') && (
                                        <button
                                            type="button"
                                            aria-label={`Pause upload ${item.name}`}
                                            onClick={() => uploadManagerRef.current?.pause(item.id)}
                                            className="inline-flex items-center gap-1 text-indigo-300"
                                        >
                                            <Pause size={12} />
                                            <span>Pause</span>
                                        </button>
                                    )}

                                    {(item.status === 'paused' || item.status === 'pausing') && (
                                        <button
                                            type="button"
                                            aria-label={`Resume upload ${item.name}`}
                                            onClick={() => uploadManagerRef.current?.resume(item.id)}
                                            className="inline-flex items-center gap-1 text-emerald-300"
                                        >
                                            <Play size={12} />
                                            <span>Resume</span>
                                        </button>
                                    )}

                                    {(item.status === 'pending' ||
                                        item.status === 'uploading' ||
                                        item.status === 'pausing' ||
                                        item.status === 'paused') && (
                                        <button
                                            type="button"
                                            aria-label={`Cancel upload ${item.name}`}
                                            onClick={() => uploadManagerRef.current?.cancel(item.id)}
                                            className="text-amber-300"
                                        >
                                            Cancel
                                        </button>
                                    )}

                                    {item.status === 'error' && (
                                        <span className="text-rose-400 font-medium" title={item.error}>
                                            {item.error || 'Failed'}
                                        </span>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
            <div
                className={`obs-canvas-section py-5 flex flex-col space-y-4 transition-colors ${
                    isDragging ? 'bg-indigo-500/[0.07] ring-1 ring-indigo-400/50' : ''
                }`}
            >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-white/[0.06]">
                    <nav
                        aria-label="Breadcrumb"
                        className="flex items-center gap-1.5 overflow-x-auto py-1 max-w-full min-w-0"
                    >
                        <button
                            type="button"
                            onClick={handleNavigateUp}
                            disabled={!currentPath || isLoading || anyBusy}
                            aria-label="Navigate to parent folder"
                            title="Up one level"
                            className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0 mr-1"
                        >
                            <ArrowUp size={14} />
                        </button>

                        {breadcrumbs.map((crumb, idx) => {
                            const isLast = idx === breadcrumbs.length - 1;
                            return (
                                <React.Fragment key={crumb.path || 'root'}>
                                    {idx > 0 && (
                                        <ChevronRight size={13} className="text-slate-600 shrink-0" />
                                    )}
                                    <button
                                        type="button"
                                        onClick={() => navigateTo(crumb.path)}
                                        disabled={isLoading || anyBusy}
                                        aria-current={isLast ? 'page' : undefined}
                                        className={`obs-touch-target-standard min-h-[44px] inline-flex items-center px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors whitespace-nowrap ${
                                            isLast
                                                ? 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/30'
                                                : 'text-slate-300 hover:text-white hover:bg-white/[0.06]'
                                        }`}
                                    >
                                        {crumb.label}
                                    </button>
                                </React.Fragment>
                            );
                        })}
                    </nav>
                    <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-2 w-full sm:w-auto shrink-0">
                        <div className="relative w-full sm:w-60 min-w-0">
                            <Search
                                size={14}
                                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none"
                            />
                            <input
                                type="search"
                                value={filterQuery}
                                onChange={(changeEvent) => setFilterQuery(changeEvent.target.value)}
                                placeholder="Filter by filename..."
                                aria-label="Filter files by name"
                                className="obs-search-input obs-touch-target-standard min-h-[44px] h-11 w-full pl-8 pr-10 py-2 rounded-xl bg-black/40 border border-white/10 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500/50"
                            />
                            {filterQuery && (
                                <button
                                    type="button"
                                    onClick={() => setFilterQuery('')}
                                    aria-label="Clear filename filter"
                                    className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center absolute right-0 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white rounded-xl"
                                >
                                    <X size={13} />
                                </button>
                            )}
                        </div>

                        <div className="flex flex-wrap items-center gap-1 bg-black/30 border border-white/10 rounded-xl p-1 shrink-0">
                            {(['name', 'size', 'modified'] as SortField[]).map((field) => {
                                const active = sortField === field;
                                return (
                                    <button
                                        key={field}
                                        type="button"
                                        onClick={() => toggleSort(field)}
                                        aria-label={`Sort by ${field}`}
                                        className={`obs-touch-target-standard min-h-[44px] flex items-center justify-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-colors ${
                                            active
                                                ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                                : 'text-slate-400 hover:text-slate-200'
                                        }`}
                                    >
                                        <span>{field}</span>
                                        {active && (
                                            <span className="text-xs font-mono">
                                                {sortDirection === 'asc' ? '↑' : '↓'}
                                            </span>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    </div>
                </div>
                {selectedEntry && (
                    <div
                        role="region"
                        aria-label="Selected item actions"
                        className="flex flex-wrap items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30"
                    >
                        <div className="flex items-center gap-2.5 min-w-0">
                            <span className="text-xs font-bold text-indigo-200 truncate">
                                Selected: {selectedEntry.name}
                            </span>
                            <span className="text-xs px-2 py-0.5 rounded-full bg-white/10 text-slate-300 uppercase font-mono">
                                {selectedEntry.kind}
                            </span>
                            {selectedEntry.kind === 'symlink' || selectedEntry.kind === 'other' ? (
                                <span className="text-xs text-amber-300 flex items-center gap-1">
                                    <Link2Off size={13} />
                                    {selectedEntry.kind === 'symlink' ? 'Symbolic link — rename and delete affect the link only' : 'Unsupported entry type — navigation and file mutations are disabled'}
                                </span>
                            ) : null}
                        </div>

                        <div className="flex flex-wrap items-center gap-2">
                            {getMcBrowserEntryTargetKind(selectedEntry) === 'directory' && (
                                <button
                                    type="button"
                                    onClick={() => navigateTo(selectedEntry.path)}
                                    disabled={anyBusy}
                                    className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-500/20 text-indigo-200 hover:bg-indigo-500/30 border border-indigo-500/30 transition-colors inline-flex items-center"
                                >
                                    Open Folder
                                </button>
                            )}
                            {getMcBrowserEntryTargetKind(selectedEntry) === 'file' && (
                                <>
                                    <button
                                        type="button"
                                        onClick={(event) => void handleOpenPreview(selectedEntry, event.currentTarget)}
                                        disabled={!permissions.read || anyBusy}
                                        className="obs-touch-target-standard min-h-[44px] flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.06] text-slate-200 hover:bg-white/10 border border-white/10 transition-colors"
                                    >
                                        <Eye size={13} />
                                        <span>Preview</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => handleDownload(selectedEntry)}
                                        disabled={!permissions.download || anyBusy || downloadingPath === selectedEntry.path}
                                        className="obs-touch-target-standard min-h-[44px] flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.06] text-slate-200 hover:bg-white/10 border border-white/10 transition-colors"
                                    >
                                        <Download size={13} />
                                        <span>Download</span>
                                    </button>
                                </>
                            )}
                            {selectedEntry.kind !== 'other' && (
                                <>
                                    <button
                                        type="button"
                                        onClick={(event) => openRenameDialog(selectedEntry, event.currentTarget)}
                                        disabled={!permissions.rename || anyBusy}
                                        className="obs-touch-target-standard min-h-[44px] flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/[0.06] text-slate-200 hover:bg-white/10 border border-white/10 transition-colors"
                                    >
                                        <Edit3 size={13} />
                                        <span>Rename</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={(event) => openDeleteDialog(selectedEntry, event.currentTarget)}
                                        disabled={!permissions.delete || anyBusy}
                                        className="obs-touch-target-standard min-h-[44px] flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-rose-500/15 text-rose-300 hover:bg-rose-500/25 border border-rose-500/30 transition-colors"
                                    >
                                        <Trash2 size={13} />
                                        <span>Delete</span>
                                    </button>
                                </>
                            )}
                        </div>
                    </div>
                )}
                {loadError ? (
                    <div
                        role="alert"
                        className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-6 flex flex-col items-center justify-center text-center gap-3"
                    >
                        <AlertTriangle size={28} className="text-rose-400" />
                        <div>
                            <h3 className="text-sm font-bold text-slate-100">Unable to load directory</h3>
                            <p className="text-xs text-rose-200/90 mt-1 max-w-md">{loadError}</p>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                            <button
                                type="button"
                                onClick={() => fetchDirectory(currentPath)}
                                className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-rose-500/20 border border-rose-500/40 text-rose-200 hover:bg-rose-500/30 transition-colors"
                            >
                                Retry
                            </button>
                            {currentPath && (
                                <button
                                    type="button"
                                    onClick={() => navigateTo('')}
                                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-white/5 border border-white/10 text-slate-200 hover:bg-white/10 transition-colors"
                                >
                                    Return to My files
                                </button>
                            )}
                        </div>
                    </div>
                ) : isLoading ? (
                    <div
                        role="status"
                        aria-live="polite"
                        className="py-16 flex flex-col items-center justify-center text-slate-400 gap-3"
                    >
                        <Loader2 size={32} className="animate-spin text-indigo-400" />
                        <p className="text-xs font-medium tracking-wide">Loading My files...</p>
                    </div>
                ) : filteredAndSortedEntries.length === 0 ? (
                    <div className="py-16 flex flex-col items-center justify-center text-center gap-2">
                        <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-slate-500 mb-1">
                            <Folder size={24} />
                        </div>
                        {filterQuery.trim() ? (
                            <>
                                <p className="text-sm font-semibold text-slate-200">
                                    No matching entries for &ldquo;{filterQuery.trim()}&rdquo;
                                </p>
                                <p className="text-xs text-slate-500">
                                    Try clearing the filename filter to see all items in this folder.
                                </p>
                            </>
                        ) : (
                            <>
                                <p className="text-sm font-semibold text-slate-200">
                                    This folder is empty
                                </p>
                                <p className="text-xs text-slate-500 max-w-sm">
                                    Create a new folder or upload files (up to {formatBytes(maxUploadBytes)} per file) to get started.
                                </p>
                            </>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto min-w-0 max-w-full">
                        <table
                            aria-label="Directory entries"
                            className="w-full text-left border-collapse block xl:table xl:table-fixed min-w-0"
                        >
                            <thead className="sr-only xl:not-sr-only xl:table-header-group">
                                <tr className="border-b border-white/[0.08] text-xs font-bold uppercase tracking-wider text-slate-400">
                                    <th id="header-name" scope="col" aria-label="Name" aria-sort={sortField === 'name' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-2.5 px-3 xl:w-[38%]">
                                        <button
                                            type="button"
                                            onClick={() => toggleSort("name")}
                                            className="obs-touch-target-standard min-h-[44px] hidden xl:inline-flex items-center gap-1 hover:text-white transition-colors"
                                        >
                                            <span>Name</span>
                                            <ArrowUpDown size={12} />
                                        </button>
                                    </th>
                                    <th id="header-kind" scope="col" className="py-2.5 px-3 xl:w-[10%]">
                                        Kind
                                    </th>
                                    <th id="header-size" scope="col" aria-label="Size" aria-sort={sortField === 'size' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-2.5 px-3 xl:w-[10%]">
                                        <button
                                            type="button"
                                            onClick={() => toggleSort("size")}
                                            className="obs-touch-target-standard min-h-[44px] hidden xl:inline-flex items-center gap-1 hover:text-white transition-colors"
                                        >
                                            <span>Size</span>
                                            <ArrowUpDown size={12} />
                                        </button>
                                    </th>
                                    <th id="header-modified" scope="col" aria-label="Modified" aria-sort={sortField === 'modified' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-2.5 px-3 xl:w-[18%]">
                                        <button
                                            type="button"
                                            onClick={() => toggleSort("modified")}
                                            className="obs-touch-target-standard min-h-[44px] hidden xl:inline-flex items-center gap-1 hover:text-white transition-colors"
                                        >
                                            <span>Modified</span>
                                            <ArrowUpDown size={12} />
                                        </button>
                                    </th>
                                    <th id="header-actions" scope="col" className="py-2.5 px-3 text-right xl:w-[24%]">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.04] block xl:table-row-group text-sm">
                                {filteredAndSortedEntries.map((entry) => {
                                    const isSelected = selectedPath === entry.path;
                                    const isUnsupported =
                                        entry.kind === "other";
                                    const isDownloading = downloadingPath === entry.path;

                                    return (
                                        <tr
                                            key={entry.path}
                                            aria-selected={isSelected}
                                            onClick={() => setSelectedPath(entry.path)}
                                            className={`group transition-colors block xl:table-row p-3.5 sm:p-4 xl:p-0 border-b border-white/[0.06] xl:border-b-0 ${
                                                isSelected
                                                    ? "bg-indigo-500/15"
                                                    : "hover:bg-white/[0.04]"
                                            }`}
                                        >
                                            <td headers="header-name" className="block xl:table-cell py-0 xl:py-2.5 px-0 xl:px-3 min-w-0">
                                                <div className="flex items-start sm:items-center gap-3 min-w-0">
                                                    <div
                                                        className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border mt-1 sm:mt-0 ${
                                                            entry.kind === "directory"
                                                                ? "bg-indigo-500/15 border-indigo-500/30 text-indigo-400"
                                                                : entry.kind === "file"
                                                                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                                                                : "bg-amber-500/15 border-amber-500/30 text-amber-400"
                                                        }`}
                                                    >
                                                        {entry.kind === "directory" ? (
                                                            <Folder size={16} />
                                                        ) : entry.kind === "file" ? (
                                                            <FileText size={16} />
                                                        ) : entry.kind === "symlink" ? (
                                                            <Link2Off size={16} />
                                                        ) : (
                                                            <FileQuestion size={16} />
                                                        )}
                                                    </div>

                                                    {isUnsupported ? (
                                                        <div className="min-w-0 flex-1">
                                                            <div className="flex items-center gap-2 flex-wrap">
                                                                <span className="font-medium text-slate-300 break-words [overflow-wrap:anywhere]">
                                                                    {entry.name}
                                                                </span>
                                                                <span className="text-xs font-bold uppercase px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30 shrink-0">
                                                                    {entry.kind === "symlink"
                                                                        ? "Symlink (Unsupported)"
                                                                        : "Unsupported Type"}
                                                                </span>
                                                            </div>
                                                            <p className="text-xs text-amber-300/80 mt-0.5">
                                                                Special files cannot be opened or modified.
                                                            </p>
                                                        </div>
                                                    ) : (
                                                        <button
                                                            type="button"
                                                            onClick={(event) => {
                                                                event.stopPropagation();
                                                                setSelectedPath(entry.path);
                                                                handleEntryActivate(entry);
                                                            }}
                                                            disabled={anyBusy || getMcBrowserEntryTargetKind(entry) === "symlink"}
                                                            title={entry.kind === "symlink" ? "Internal links can be opened; rename and delete affect the link only" : undefined}
                                                            className="obs-touch-target-standard min-h-[44px] min-w-0 flex-1 text-left font-medium text-slate-100 hover:text-indigo-300 focus:outline-none focus-visible:underline break-words [overflow-wrap:anywhere] block py-2"
                                                        >
                                                            {entry.name}
                                                        </button>
                                                    )}
                                                </div>
                                            </td>

                                            <td headers="header-kind" className="inline-block xl:table-cell py-0 xl:py-2.5 px-0 xl:px-3 text-xs mt-2 xl:mt-0 mr-4 xl:mr-0">
                                                <span className="xl:hidden text-slate-400 font-sans mr-1.5 uppercase font-medium text-xs">Kind:</span>
                                                <span className="font-mono text-slate-400 capitalize">
                                                    {entry.kind}
                                                </span>
                                            </td>

                                            <td headers="header-size" className="inline-block xl:table-cell py-0 xl:py-2.5 px-0 xl:px-3 text-xs font-mono text-slate-300 whitespace-nowrap mt-2 xl:mt-0 mr-4 xl:mr-0">
                                                <span className="xl:hidden text-slate-400 font-sans mr-1.5 uppercase font-medium text-xs">Size:</span>
                                                {getMcBrowserEntryTargetKind(entry) === "directory"
                                                    ? "—"
                                                    : formatBytes(entry.size)}
                                            </td>

                                            <td headers="header-modified" className="inline-block xl:table-cell py-0 xl:py-2.5 px-0 xl:px-3 text-xs text-slate-400 whitespace-nowrap mt-2 xl:mt-0">
                                                <span className="xl:hidden text-slate-400 font-sans mr-1.5 uppercase font-medium text-xs">Modified:</span>
                                                {formatModifiedDate(entry.modified)}
                                            </td>

                                            <td
                                                headers="header-actions"
                                                className="block xl:table-cell py-0 xl:py-2.5 px-0 xl:px-3 text-left xl:text-right mt-3 xl:mt-0 pt-2.5 xl:pt-0 border-t border-white/[0.06] xl:border-t-0"
                                                onClick={(event) => event.stopPropagation()}
                                            >
                                                {isUnsupported ? (
                                                    <span className="text-xs text-amber-400/80 italic px-2">
                                                        Unsupported
                                                    </span>
                                                ) : (
                                                    <div className="flex flex-wrap xl:flex-nowrap items-center justify-start xl:justify-end gap-1">
                                                        {getMcBrowserEntryTargetKind(entry) === "directory" && (
                                                            <button
                                                                type="button"
                                                                onClick={() => navigateTo(entry.path)}
                                                                disabled={anyBusy}
                                                                aria-label={`Open folder ${entry.name}`}
                                                                title="Open folder"
                                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl text-slate-400 hover:text-indigo-300 hover:bg-white/10 disabled:opacity-40 transition-colors"
                                                            >
                                                                <ChevronRight size={15} />
                                                            </button>
                                                        )}

                                                        {getMcBrowserEntryTargetKind(entry) === "file" && (
                                                            <>
                                                                <button
                                                                    type="button"
                                                                    onClick={(event) => void handleOpenPreview(entry, event.currentTarget)}
                                                                    disabled={!permissions.read || anyBusy}
                                                                    aria-label={`Preview ${entry.name}`}
                                                                    title="Preview text"
                                                                    className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl text-slate-400 hover:text-indigo-300 hover:bg-white/10 disabled:opacity-40 transition-colors"
                                                                >
                                                                    <Eye size={15} />
                                                                </button>

                                                                <button
                                                                    type="button"
                                                                    onClick={() => handleDownload(entry)}
                                                                    disabled={!permissions.download || anyBusy || isDownloading}
                                                                    aria-label={`Download ${entry.name}`}
                                                                    title="Download file"
                                                                    className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl text-slate-400 hover:text-emerald-300 hover:bg-white/10 disabled:opacity-40 transition-colors"
                                                                >
                                                                    {isDownloading ? (
                                                                        <Loader2
                                                                            size={15}
                                                                            className="animate-spin text-emerald-400"
                                                                        />
                                                                    ) : (
                                                                        <Download size={15} />
                                                                    )}
                                                                </button>
                                                            </>
                                                        )}

                                                        <button
                                                            type="button"
                                                            onClick={(event) => openRenameDialog(entry, event.currentTarget)}
                                                            disabled={!permissions.rename || anyBusy}
                                                            aria-label={`Rename ${entry.name}`}
                                                            title="Rename"
                                                            className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-white/10 disabled:opacity-40 transition-colors"
                                                        >
                                                            <Edit3 size={15} />
                                                        </button>

                                                        <button
                                                            type="button"
                                                            onClick={(event) => openDeleteDialog(entry, event.currentTarget)}
                                                            disabled={!permissions.delete || anyBusy}
                                                            aria-label={`Delete ${entry.name}`}
                                                            title="Delete"
                                                            className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 rounded-xl text-slate-400 hover:text-rose-400 hover:bg-rose-500/15 disabled:opacity-40 transition-colors"
                                                        >
                                                            <Trash2 size={15} />
                                                        </button>
                                                    </div>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
            {hasActivated && (
                <details className="obs-canvas-section group">
                    <summary className="obs-touch-target-standard min-h-[44px] cursor-pointer px-1 py-3 text-sm font-semibold text-slate-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400">
                        Advanced workspace &mdash; batch operations, editor &amp; share links
                    </summary>
                    <div className="pt-2">
                        <McBrowserWorkspace
                            key={`mcbrowser-workspace-${sessionIdentity}-${sessionEpoch}`}
                            currentPath={currentPath}
                            entries={entries}
                            onRefresh={handleWorkspaceRefresh}
                            onNavigate={navigateTo}
                            onPolicyChange={handlePolicyChange}
                            onRename={openRenameDialog}
                        />
                    </div>
                </details>
            )}
            {mediaTarget && (
                <McBrowserMediaPreview
                    entry={mediaTarget}
                    entries={entries}
                    permissions={permissions}
                    onClose={() => setMediaTarget(null)}
                    onSelectEntry={setMediaTarget}
                    onDownload={handleDownload}
                    onRename={(entry) => {
                        setMediaTarget(null);
                        openRenameDialog(entry);
                    }}
                    onDelete={(entry) => {
                        setMediaTarget(null);
                        openDeleteDialog(entry);
                    }}
                />
            )}
            {mkdirOpen && (
                <Modal
                    isOpen={mkdirOpen}
                    onClose={() => {
                        if (!isMutating) setMkdirOpen(false);
                    }}
                    title="Create New Folder"
                    initialFocusRef={mkdirInputRef}
                    returnFocusRef={mkdirOpenerRef}
                >
                    <form onSubmit={handleCreateDirectory} className="space-y-4">
                        <div>
                            <label
                                htmlFor="mcbrowser-mkdir-input"
                                className="block text-xs font-semibold text-slate-300 mb-1.5"
                            >
                                Folder Name
                            </label>
                            <input
                                ref={mkdirInputRef}
                                id="mcbrowser-mkdir-input"
                                type="text"
                                value={mkdirName}
                                onChange={(event) => {
                                    setMkdirName(event.target.value);
                                    if (mkdirError) setMkdirError(null);
                                }}
                                placeholder="e.g. configs"
                                disabled={isMutating}
                                className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/15 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                            />
                            <p className="text-xs text-slate-400 mt-1.5">
                                Will be created inside{' '}
                                <span className="font-mono text-slate-200">
                                    {currentPath ? `My files/${currentPath}` : 'My files'}
                                </span>
                            </p>
                        </div>

                        {mkdirError && (
                            <div
                                role="alert"
                                className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                            >
                                {mkdirError}
                            </div>
                        )}

                        <div className="flex items-center justify-end gap-2 pt-2">
                            <button
                                type="button"
                                onClick={() => setMkdirOpen(false)}
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300 hover:bg-white/10 disabled:opacity-50 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-50 transition-colors"
                            >
                                {isMutating && <Loader2 size={14} className="animate-spin" />}
                                <span>Create Folder</span>
                            </button>
                        </div>
                    </form>
                </Modal>
            )}
            {renameTarget && (
                <Modal
                    isOpen={Boolean(renameTarget)}
                    onClose={() => {
                        if (!isMutating) setRenameTarget(null);
                    }}
                    title={`Rename ${renameTarget.kind === 'symlink' ? 'Link' : renameTarget.kind === 'directory' ? 'Folder' : 'File'}`}
                    initialFocusRef={renameInputRef}
                    returnFocusRef={renameOpenerRef}
                >
                    <form onSubmit={handleRenameSubmit} className="space-y-4">
                        <div>
                            <label
                                htmlFor="mcbrowser-rename-input"
                                className="block min-w-0 max-w-full break-words [overflow-wrap:anywhere] text-xs font-semibold text-slate-300 mb-1.5"
                            >
                                New Name for &ldquo;{renameTarget.name}&rdquo;
                            </label>
                            <input
                                ref={renameInputRef}
                                id="mcbrowser-rename-input"
                                type="text"
                                value={renameValue}
                                onChange={(event) => {
                                    setRenameValue(event.target.value);
                                    if (renameError) setRenameError(null);
                                }}
                                disabled={isMutating}
                                className="w-full px-3.5 py-2.5 rounded-xl bg-black/50 border border-white/15 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                            />
                            <p className="text-xs text-slate-400 mt-1.5">
                                Existing files or folders are never overwritten during rename.
                            </p>
                        </div>

                        {renameError && (
                            <div
                                role="alert"
                                className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                            >
                                {renameError}
                            </div>
                        )}

                        <div className="flex items-center justify-end gap-2 pt-2">
                            <button
                                type="button"
                                onClick={() => setRenameTarget(null)}
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300 hover:bg-white/10 disabled:opacity-50 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-50 transition-colors"
                            >
                                {isMutating && <Loader2 size={14} className="animate-spin" />}
                                <span>Confirm Rename</span>
                            </button>
                        </div>
                    </form>
                </Modal>
            )}
            {deleteTarget && (
                <Modal
                    isOpen={Boolean(deleteTarget)}
                    onClose={() => {
                        if (!isMutating) setDeleteTarget(null);
                    }}
                    title={`Delete ${deleteTarget.kind === 'symlink' ? 'Link' : deleteTarget.kind === 'directory' ? 'Folder' : 'File'}`}
                    className="border-rose-500/30"
                    initialFocusRef={deleteCancelRef}
                    returnFocusRef={deleteOpenerRef}
                >
                    <div className="space-y-4">
                        <div className="space-y-2 text-xs text-slate-300">
                            <p>
                                Are you sure you want to permanently delete{' '}
                                <span className="font-bold text-white">&ldquo;{deleteTarget.name}&rdquo;</span>?
                            </p>
                            {deleteTarget.kind === 'directory' ? (
                                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 flex items-start gap-2">
                                    <Info size={15} className="shrink-0 mt-0.5 text-amber-400" />
                                    <span>
                                        Server policy only permits deleting <strong>empty directories</strong>. If this folder contains files, deletion will be rejected.
                                    </span>
                                </div>
                            ) : (
                                <p className="text-slate-400">
                                    This action cannot be undone.
                                </p>
                            )}
                        </div>

                        {deleteError && (
                            <div
                                role="alert"
                                className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                            >
                                {deleteError}
                            </div>
                        )}

                        <div className="flex items-center justify-end gap-2 pt-2">
                            <button
                                ref={deleteCancelRef}
                                type="button"
                                onClick={() => setDeleteTarget(null)}
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300 hover:bg-white/10 disabled:opacity-50 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={handleDeleteConfirm}
                                disabled={isMutating}
                                className="obs-touch-target-standard min-h-[44px] flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white disabled:opacity-50 transition-colors"
                            >
                                {isMutating && <Loader2 size={14} className="animate-spin" />}
                                <span>Confirm Delete</span>
                            </button>
                        </div>
                    </div>
                </Modal>
            )}
            {previewTarget && (
                <Modal
                    isOpen={Boolean(previewTarget)}
                    onClose={closePreviewDialog}
                    title={`Preview: ${previewTarget.name}`}
                    className="max-w-3xl"
                    initialFocusRef={previewDownloadRef}
                    returnFocusRef={previewOpenerRef}
                >
                    <div className="flex flex-col space-y-4">
                        <div className="flex flex-wrap items-center justify-between gap-3 -mt-2 pb-3 border-b border-white/10">
                            <p className="text-xs text-slate-400 font-mono truncate">
                                My files/{previewTarget.path} ({formatBytes(previewTarget.size)})
                            </p>
                            <button
                                ref={previewDownloadRef}
                                type="button"
                                onClick={() => handleDownload(previewTarget)}
                                disabled={!permissions.download || downloadingPath === previewTarget.path}
                                className="obs-touch-target-standard min-h-[44px] flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                            >
                                <Download size={14} />
                                <span>Download</span>
                            </button>
                        </div>

                        {previewData?.truncated && (
                            <div
                                role="status"
                                className="px-3.5 py-2 rounded-xl bg-amber-500/15 border border-amber-500/30 text-xs text-amber-200 flex items-center gap-2"
                            >
                                <AlertTriangle size={15} className="text-amber-400 shrink-0" />
                                <span>
                                    Preview truncated to the first {formatBytes(MAX_PREVIEW_BYTES, 0)} of UTF-8 text. Download the file to view its full contents.
                                </span>
                            </div>
                        )}

                        <div className="min-h-[220px] max-h-[55vh] overflow-auto rounded-xl bg-black/60 border border-white/10 p-4">
                            {previewLoading ? (
                                <div className="h-48 flex flex-col items-center justify-center text-slate-400 gap-2">
                                    <Loader2 size={24} className="animate-spin text-indigo-400" />
                                    <span className="text-xs">Loading UTF-8 text preview...</span>
                                </div>
                            ) : previewError ? (
                                <div
                                    role="alert"
                                    className="h-48 flex flex-col items-center justify-center text-center gap-2 text-rose-300"
                                >
                                    <AlertTriangle size={24} className="text-rose-400" />
                                    <p className="text-xs max-w-md">{previewError}</p>
                                </div>
                            ) : (
                                <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-words leading-relaxed select-text">
                                    {previewData?.content ?? ''}
                                </pre>
                            )}
                        </div>
                    </div>
                </Modal>
            )}
        </div>
    );
}
