'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
    Folder,
    FileText,
    FilePlus,
    Trash2,
    Copy,
    Move,
    Search,
    Info,
    Share2,
    Archive,
    LayoutGrid,
    List,
    Eye,
    EyeOff,
    CheckSquare,
    Square,
    Edit3,
    Save,
    RefreshCw,
    X,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    Loader2,
    Shield,
    HardDrive,
    Link2,
    Link2Off,
    FileQuestion,
    SlidersHorizontal,
    Sparkles,
} from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import McBrowserCodeEditor from '@/components/mcbrowser/McBrowserCodeEditor';
import McBrowserActions from '@/components/mcbrowser/McBrowserActions';
import {
    McBrowserConflictPolicy,
    McBrowserEntry,
    McBrowserRequestError,
    extractMcBrowserError,
    formatBytes,
    formatModifiedDate,
    getMcBrowserEntryTargetKind,
    joinRelativePath,
    normalizeRelativePath,
    renameMcBrowserEntry,
    deleteMcBrowserEntry,
    validateEntryName,
} from '@/lib/mcbrowser';
import {
    McBrowserArchiveFormat,
    McBrowserBatchItemOutcome,
    McBrowserChecksumAlgorithm,
    McBrowserFileInfoResponse,
    McBrowserPolicyPermissions,
    McBrowserPolicyResponse,
    McBrowserPreferences,
    McBrowserSearchType,
    McBrowserShareItem,
    McBrowserSortDirection,
    McBrowserSortField,
    McBrowserUsageResponse,
    classifyBatchError,
    copyMcBrowserEntry,
    createMcBrowserFile,
    createMcBrowserShare,
    deleteMcBrowserRecursive,
    downloadMcBrowserArchive,
    fetchMcBrowserContent,
    fetchMcBrowserFileInfo,
    fetchMcBrowserPolicy,
    fetchMcBrowserPreferences,
    fetchMcBrowserUsage,
    listMcBrowserShares,
    normalizeMcBrowserPreferences,
    normalizeMcBrowserViewMode,
    resolveBatchDestinationPath,
    revokeMcBrowserShare,
    saveMcBrowserContent,
    searchMcBrowserEntries,
    updateMcBrowserPreferences,
} from '@/lib/mcbrowser-workspace';

export interface McBrowserWorkspaceProps {
    currentPath: string;
    entries: McBrowserEntry[];
    onRefresh: () => void;
    onNavigate: (path: string) => void;
    onPolicyChange?: (policy: McBrowserPolicyResponse | null) => void;
    onRename?: (entry: McBrowserEntry) => void;
}

const DEFAULT_PERMISSIONS: McBrowserPolicyPermissions = {
    read: false,
    create: false,
    rename: false,
    modify: false,
    delete: false,
    share: false,
    download: false,
    execute: false,
};

const DEFAULT_PREFERENCES: Required<McBrowserPreferences> = {
    view: 'list',
    sort: 'name',
    direction: 'asc',
    show_hidden: false,
    single_click: false,
    natural_sort: true,
    redirect_after_copy_move: false,
    date_format: false,
    editor_theme: 'chrome',
    locale: 'en-US',
};

const EDITOR_THEME_OPTIONS = [
    'chrome',
    'github',
    'solarized_light',
    'monokai',
    'dracula',
    'twilight',
    'tomorrow_night',
    'solarized_dark',
] as const;

const LOCALE_OPTIONS = [
    'en-US',
    'en-GB',
    'en',
    'de',
    'es',
    'fr',
    'fr-FR',
    'it',
    'ja',
    'ko',
    'nl',
    'nl-BE',
    'pl',
    'pt-BR',
    'pt-br',
    'ru',
    'sv-se',
    'tr',
    'uk',
    'zh-CN',
    'zh-TW',
] as const;

export default function McBrowserWorkspace({
    currentPath,
    entries,
    onRefresh,
    onNavigate,
    onPolicyChange,
    onRename,
}: McBrowserWorkspaceProps) {
    const { addToast } = useToast();

    // Policy, Preferences, Usage
    const [policy, setPolicy] = useState<McBrowserPolicyResponse>({
        permissions: DEFAULT_PERMISSIONS,
        rules: [],
        scope: 'My files',
    });
    const [preferences, setPreferences] = useState<McBrowserPreferences>(DEFAULT_PREFERENCES);
    const [usage, setUsage] = useState<McBrowserUsageResponse | null>(null);
    const [usageError, setUsageError] = useState<string | null>(null);
    const [metaError, setMetaError] = useState<string | null>(null);
    const [prefsSaving, setPrefsSaving] = useState<boolean>(false);

    // Multi-selection state
    const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
    const [selectionPath, setSelectionPath] = useState(currentPath);
    const [actionsOpen, setActionsOpen] = useState(false);

    // Recursive Server Search state
    const [searchQuery, setSearchQuery] = useState<string>('');
    const [searchType, setSearchType] = useState<McBrowserSearchType>('all');
    const [searchAiMode, setSearchAiMode] = useState<boolean>(true);
    const [searchAiInterpretation, setSearchAiInterpretation] = useState<string | null>(null);
    const [searchResults, setSearchResults] = useState<McBrowserEntry[] | null>(null);
    const [searchTruncated, setSearchTruncated] = useState<boolean>(false);
    const [searchLoading, setSearchLoading] = useState<boolean>(false);
    const [searchError, setSearchError] = useState<string | null>(null);

    // New File Dialog state
    const [newFileOpen, setNewFileOpen] = useState<boolean>(false);
    const [newFileName, setNewFileName] = useState<string>('');
    const [newFileContent, setNewFileContent] = useState<string>('');
    const [newFileError, setNewFileError] = useState<string | null>(null);
    const [newFileBusy, setNewFileBusy] = useState<boolean>(false);

    // UTF-8 Editor Dialog state
    const [editorTarget, setEditorTarget] = useState<McBrowserEntry | null>(null);
    const [editorContent, setEditorContent] = useState<string>('');
    const [editorSavedContent, setEditorSavedContent] = useState('');
    const [editorDiscardAction, setEditorDiscardAction] = useState<'close' | 'reload' | null>(null);
    const [editorEtag, setEditorEtag] = useState<string>('');
    const [editorLoading, setEditorLoading] = useState<boolean>(false);
    const [editorSaving, setEditorSaving] = useState<boolean>(false);
    const [editorError, setEditorError] = useState<string | null>(null);
    const [editorStaleConflict, setEditorStaleConflict] = useState<boolean>(false);

    // File Info & Checksum Dialog state
    const [infoTarget, setInfoTarget] = useState<McBrowserEntry | null>(null);
    const [infoChecksumAlg, setInfoChecksumAlg] = useState<McBrowserChecksumAlgorithm>('sha256');
    const [infoData, setInfoData] = useState<McBrowserFileInfoResponse | null>(null);
    const [infoLoading, setInfoLoading] = useState<boolean>(false);
    const [infoError, setInfoError] = useState<string | null>(null);

    // Batch Move / Copy / Delete Dialog state
    const [batchMode, setBatchMode] = useState<'move' | 'copy' | 'delete' | null>(null);
    const [batchTargets, setBatchTargets] = useState<McBrowserEntry[]>([]);
    const [clipboard, setClipboard] = useState<{
        mode: 'copy' | 'move';
        entries: McBrowserEntry[];
        sourcePath: string;
    } | null>(null);
    const [batchFromClipboard, setBatchFromClipboard] = useState(false);
    const [batchDestinationDir, setBatchDestinationDir] = useState<string>('');
    const [batchConflictPolicy, setBatchConflictPolicy] = useState<McBrowserConflictPolicy>('error');
    const [batchRecursiveDelete, setBatchRecursiveDelete] = useState<boolean>(true);
    const [batchRunning, setBatchRunning] = useState<boolean>(false);
    const [batchError, setBatchError] = useState<string | null>(null);
    const [batchOutcomes, setBatchOutcomes] = useState<McBrowserBatchItemOutcome[]>([]);

    // Archive Download state
    const [archiveFormat, setArchiveFormat] = useState<McBrowserArchiveFormat>('zip');
    const [archiveDownloading, setArchiveDownloading] = useState<boolean>(false);
    const [archiveError, setArchiveError] = useState<string | null>(null);
    const [lastArchiveMessage, setLastArchiveMessage] = useState<string | null>(null);

    // Share Links Dialog state
    const [sharesOpen, setSharesOpen] = useState<boolean>(false);
    const [sharesList, setSharesList] = useState<McBrowserShareItem[]>([]);
    const [sharesLoading, setSharesLoading] = useState<boolean>(false);
    const [sharesError, setSharesError] = useState<string | null>(null);
    const [shareTargetPath, setShareTargetPath] = useState<string>('');
    const [sharePassword, setSharePassword] = useState<string>('');
    const [shareExpiresAt, setShareExpiresAt] = useState<string>('');
    const [shareAllowDownload, setShareAllowDownload] = useState<boolean>(true);
    const [shareSubmitting, setShareSubmitting] = useState<boolean>(false);
    const [revokingShareId, setRevokingShareId] = useState<string | null>(null);

    // Abort & sequence refs
    const metaAbortRef = useRef<AbortController | null>(null);
    const searchAbortRef = useRef<AbortController | null>(null);
    const searchSeqRef = useRef<number>(0);
    const editorAbortRef = useRef<AbortController | null>(null);
    const editorSeqRef = useRef<number>(0);
    const editorSaveInFlightRef = useRef(false);
    const infoAbortRef = useRef<AbortController | null>(null);
    const infoSeqRef = useRef<number>(0);
    const sharesAbortRef = useRef<AbortController | null>(null);
    const archiveAbortRef = useRef<AbortController | null>(null);
    const searchInputRef = useRef<HTMLInputElement | null>(null);

    const permissions = policy.permissions;
    const editorDirty = editorTarget !== null && editorContent !== editorSavedContent;
    const normalizedView = normalizeMcBrowserViewMode(preferences.view);

    if (selectionPath !== currentPath) {
        setSelectionPath(currentPath);
        setSelectedPaths([]);
        setSearchResults(null);
        setSearchTruncated(false);
        setSearchAiInterpretation(null);
        setSearchLoading(false);
        setSearchError(null);
    }

    useEffect(() => {
        searchAbortRef.current?.abort();
        searchSeqRef.current += 1;
    }, [currentPath]);

    useEffect(() => {
        if (!editorDirty) return;
        const warnBeforeUnload = (event: BeforeUnloadEvent) => {
            event.preventDefault();
            event.returnValue = '';
        };
        window.addEventListener('beforeunload', warnBeforeUnload);
        return () => window.removeEventListener('beforeunload', warnBeforeUnload);
    }, [editorDirty]);

    const formatWorkspaceDate = useCallback(
        (modified: string | null | undefined): string => {
            if (!modified) return '\u2014';
            const parsed = new Date(modified);
            if (Number.isNaN(parsed.getTime())) {
                return formatModifiedDate(modified);
            }
            if (preferences.date_format) {
                return parsed.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
            }
            try {
                return parsed.toLocaleString(preferences.locale || undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                });
            } catch {
                return formatModifiedDate(modified);
            }
        },
        [preferences.date_format, preferences.locale]
    );

    useEffect(() => {
        const controller = new AbortController();
        metaAbortRef.current = controller;

        void Promise.allSettled([
            fetchMcBrowserPolicy(controller.signal),
            fetchMcBrowserPreferences(controller.signal),
        ]).then(([policyRes, prefsRes]) => {
            if (controller.signal.aborted) return;

            const errors: string[] = [];
            if (policyRes.status === 'fulfilled' && policyRes.value?.permissions) {
                const loadedPolicy = {
                    permissions: { ...DEFAULT_PERMISSIONS, ...policyRes.value.permissions },
                    rules: Array.isArray(policyRes.value.rules) ? policyRes.value.rules : [],
                    scope: policyRes.value.scope || 'My files',
                };
                setPolicy(loadedPolicy);
                onPolicyChange?.(loadedPolicy);
            } else if (policyRes.status === 'rejected') {
                onPolicyChange?.(null);
                const reason = policyRes.reason;
                if (!(reason instanceof Error && reason.name === 'AbortError')) {
                    errors.push(extractMcBrowserError(reason, 'Policy unavailable'));
                }
            }

            if (prefsRes.status === 'fulfilled' && prefsRes.value) {
                setPreferences((prev) =>
                    normalizeMcBrowserPreferences({
                        ...prev,
                        ...prefsRes.value,
                    })
                );
            } else if (prefsRes.status === 'rejected') {
                const reason = prefsRes.reason;
                if (!(reason instanceof Error && reason.name === 'AbortError')) {
                    errors.push(extractMcBrowserError(reason, 'Preferences unavailable'));
                }
            }

            setMetaError(errors.length > 0 ? errors.join(' \u00b7 ') : null);
        });

        return () => {
            controller.abort();
            searchAbortRef.current?.abort();
            editorAbortRef.current?.abort();
            editorSeqRef.current += 1;
            infoAbortRef.current?.abort();
            sharesAbortRef.current?.abort();
            archiveAbortRef.current?.abort();
        };
    }, [onPolicyChange]);

    useEffect(() => {
        const controller = new AbortController();
        void fetchMcBrowserUsage(controller.signal).then((updatedUsage) => {
            if (controller.signal.aborted) return;
            setUsage(updatedUsage);
            setUsageError(null);
        }).catch((error: unknown) => {
            if (controller.signal.aborted) return;
            setUsage(null);
            setUsageError(extractMcBrowserError(error, 'Usage unavailable'));
        });
        return () => controller.abort();
    }, [currentPath, entries]);

    // Keep selection synced with available entries (or search results if active)
    const activeSourceEntries = useMemo(
        () => (searchResults !== null ? searchResults : entries),
        [searchResults, entries]
    );

    const visibleEntries = useMemo(() => {
        const filtered = preferences.show_hidden
            ? [...activeSourceEntries]
            : activeSourceEntries.filter((entry) => !entry.name.startsWith('.'));

        const useNaturalSort = preferences.natural_sort !== false;
        const sortLocale = preferences.locale || undefined;

        filtered.sort((a, b) => {
            const aIsDir = getMcBrowserEntryTargetKind(a) === 'directory' ? 0 : 1;
            const bIsDir = getMcBrowserEntryTargetKind(b) === 'directory' ? 0 : 1;
            if (aIsDir !== bIsDir) {
                return aIsDir - bIsDir;
            }
            let cmp = 0;
            if (preferences.sort === 'name') {
                try {
                    cmp = a.name.localeCompare(b.name, sortLocale, {
                        numeric: useNaturalSort,
                        sensitivity: 'base',
                    });
                } catch {
                    cmp = a.name.localeCompare(b.name, undefined, {
                        numeric: useNaturalSort,
                        sensitivity: 'base',
                    });
                }
            } else if (preferences.sort === 'size') {
                cmp = (a.size || 0) - (b.size || 0);
            } else if (preferences.sort === 'modified') {
                const aTime = a.modified ? Date.parse(a.modified) || 0 : 0;
                const bTime = b.modified ? Date.parse(b.modified) || 0 : 0;
                cmp = aTime - bTime;
            }
            return preferences.direction === 'asc' ? cmp : -cmp;
        });

        return filtered;
    }, [
        activeSourceEntries,
        preferences.show_hidden,
        preferences.sort,
        preferences.direction,
        preferences.natural_sort,
        preferences.locale,
    ]);

    const selectableVisibleEntries = useMemo(
        () => visibleEntries.filter((e) => e.kind === 'file' || e.kind === 'directory' || e.kind === 'symlink'),
        [visibleEntries]
    );

    const selectedEntries = useMemo(() => {
        const byPath = new Map(activeSourceEntries.map((e) => [e.path, e]));
        return selectedPaths.map((p) => byPath.get(p)).filter((e): e is McBrowserEntry => Boolean(e));
    }, [activeSourceEntries, selectedPaths]);

    const hasUnsupportedArchiveEntries = useMemo(
        () => selectedEntries.some((entry) => {
            const kind = getMcBrowserEntryTargetKind(entry);
            return kind !== 'file' && kind !== 'directory';
        }),
        [selectedEntries]
    );

    const hasUnsupportedCopyEntries = useMemo(
        () => selectedEntries.some((entry) => {
            const kind = getMcBrowserEntryTargetKind(entry);
            return kind !== 'file' && kind !== 'directory';
        }),
        [selectedEntries]
    );

    const toggleSelectPath = (path: string, extendRange = false) => {
        if (extendRange && selectedPaths.length > 0) {
            const anchor = visibleEntries.findIndex((entry) => entry.path === selectedPaths[0]);
            const target = visibleEntries.findIndex((entry) => entry.path === path);
            if (anchor >= 0 && target >= 0) {
                const range = visibleEntries.slice(Math.min(anchor, target), Math.max(anchor, target) + 1)
                    .filter((entry) => entry.kind !== 'other').map((entry) => entry.path);
                setSelectedPaths((current) => Array.from(new Set([...current, ...range])));
                return;
            }
        }
        setSelectedPaths((prev) =>
            prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path]
        );
    };

    const toggleSelectAllVisible = () => {
        const selectablePaths = selectableVisibleEntries.map((e) => e.path);
        const allSelected =
            selectablePaths.length > 0 && selectablePaths.every((p) => selectedPaths.includes(p));
        if (allSelected) {
            setSelectedPaths((prev) => prev.filter((p) => !selectablePaths.includes(p)));
        } else {
            setSelectedPaths((prev) => Array.from(new Set([...prev, ...selectablePaths])));
        }
    };

    // Preferences Update Handler
    const handleUpdatePreferences = async (patch: Partial<McBrowserPreferences>) => {
        const nextPrefs = normalizeMcBrowserPreferences({
            ...preferences,
            ...patch,
        });
        setPreferences(nextPrefs);
        setPrefsSaving(true);
        try {
            const saved = await updateMcBrowserPreferences(nextPrefs);
            if (saved && typeof saved === 'object' && 'view' in saved) {
                setPreferences((prev) =>
                    normalizeMcBrowserPreferences({
                        ...prev,
                        ...saved,
                    })
                );
            }
        } catch (err) {
            addToast(extractMcBrowserError(err, 'Failed to persist preferences.'), 'error');
        } finally {
            setPrefsSaving(false);
        }
    };

    // Recursive Search Handlers
    const handleSearchSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!permissions.read) {
            setSearchError('Search is disabled by current read permissions policy.');
            return;
        }
        const trimmed = searchQuery.trim();
        if (!trimmed) {
            setSearchError('Enter a search term to search recursively.');
            return;
        }

        const seq = ++searchSeqRef.current;
        if (searchAbortRef.current) {
            searchAbortRef.current.abort();
        }
        const controller = new AbortController();
        searchAbortRef.current = controller;

        setSearchLoading(true);
        setSearchError(null);

        try {
            const res = await searchMcBrowserEntries(
                {
                    path: currentPath,
                    q: trimmed,
                    type: searchType,
                    ...(searchAiMode ? { ai: true } : {}),
                },
                controller.signal
            );
            if (seq !== searchSeqRef.current) return;
            setSearchResults(Array.isArray(res.entries) ? res.entries : []);
            setSearchTruncated(Boolean(res.truncated));
            setSearchAiInterpretation(
                typeof res.ai_interpretation === 'string' && res.ai_interpretation.trim()
                    ? res.ai_interpretation.trim()
                    : null
            );
        } catch (err) {
            if (seq !== searchSeqRef.current) return;
            if (err instanceof Error && err.name === 'AbortError') return;
            setSearchError(extractMcBrowserError(err, 'Recursive search failed.'));
        } finally {
            if (seq === searchSeqRef.current) {
                setSearchLoading(false);
            }
        }
    };

    const handleClearSearch = () => {
        searchSeqRef.current += 1;
        if (searchAbortRef.current) {
            searchAbortRef.current.abort();
        }
        setSearchQuery('');
        setSearchResults(null);
        setSearchTruncated(false);
        setSearchAiInterpretation(null);
        setSearchError(null);
        setSearchLoading(false);
    };

    // New File Handlers
    const openNewFileDialog = () => {
        if (!permissions.create) {
            addToast('Creating files is disabled by workspace policy.', 'error');
            return;
        }
        setNewFileName('');
        setNewFileContent('');
        setNewFileError(null);
        setNewFileOpen(true);
    };

    const handleCreateFileSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!permissions.create) {
            setNewFileError('File creation is forbidden by workspace policy.');
            return;
        }
        const trimmedName = newFileName.trim();
        const nameErr = validateEntryName(trimmedName);
        if (nameErr) {
            setNewFileError(nameErr);
            return;
        }

        let targetPath = '';
        try {
            targetPath = joinRelativePath(currentPath, trimmedName);
        } catch (err) {
            setNewFileError(extractMcBrowserError(err, 'Invalid file name.'));
            return;
        }

        setNewFileBusy(true);
        setNewFileError(null);
        try {
            await createMcBrowserFile(targetPath, newFileContent);
            addToast(`Created file "${trimmedName}"`, 'success');
            setNewFileOpen(false);
            onRefresh();
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to create file.');
            setNewFileError(msg);
            addToast(msg, 'error');
        } finally {
            setNewFileBusy(false);
        }
    };

    // UTF-8 Editor Handlers
    const loadFileIntoEditor = useCallback(
        async (entry: McBrowserEntry) => {
            if (!permissions.read) {
                addToast('Reading file content is disabled by workspace policy.', 'error');
                return;
            }
            if (getMcBrowserEntryTargetKind(entry) !== 'file') {
                addToast('Only regular files and confined file aliases can be opened in the UTF-8 editor.', 'info');
                return;
            }

            const seq = ++editorSeqRef.current;
            if (editorAbortRef.current) {
                editorAbortRef.current.abort();
            }
            const controller = new AbortController();
            editorAbortRef.current = controller;

            setEditorTarget(entry);
            setEditorContent('');
            setEditorSavedContent('');
            setEditorDiscardAction(null);
            setEditorEtag('');
            setEditorLoading(true);
            setEditorError(null);
            setEditorStaleConflict(false);

            try {
                const res = await fetchMcBrowserContent(entry.path, controller.signal);
                if (seq !== editorSeqRef.current) return;
                setEditorContent(res.content ?? '');
                setEditorSavedContent(res.content ?? '');
                setEditorEtag(res.etag ?? '');
            } catch (err) {
                if (seq !== editorSeqRef.current) return;
                if (err instanceof Error && err.name === 'AbortError') return;
                setEditorError(extractMcBrowserError(err, 'Failed to load UTF-8 file content.'));
            } finally {
                if (seq === editorSeqRef.current) {
                    setEditorLoading(false);
                }
            }
        },
        [addToast, permissions.read]
    );

    const renderAliasEditorControl = (entry: McBrowserEntry) => (
        entry.kind === 'symlink' && getMcBrowserEntryTargetKind(entry) === 'file' ? (
            <button
                type="button"
                onClick={(event) => { event.stopPropagation(); void loadFileIntoEditor(entry); }}
                disabled={!permissions.read}
                aria-label={`Edit ${entry.name}`}
                title="UTF-8 Editor — confined file target"
                className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-slate-200 disabled:opacity-40"
            >
                Edit UTF-8
            </button>
        ) : null
    );

    const handleSaveEditorContent = async (event?: React.FormEvent) => {
        event?.preventDefault();
        if (!editorTarget || !editorEtag || editorLoading || editorSaveInFlightRef.current) return;
        if (!permissions.modify) {
            setEditorError('Modifying files is forbidden by workspace policy.');
            return;
        }

        const sequence = editorSeqRef.current;
        editorSaveInFlightRef.current = true;
        setEditorSaving(true);
        setEditorError(null);
        setEditorStaleConflict(false);

        try {
            const res = await saveMcBrowserContent(editorTarget.path, editorContent, editorEtag);
            if (sequence !== editorSeqRef.current) return;
            setEditorEtag(res.etag || editorEtag);
            setEditorSavedContent(editorContent);
            setEditorDiscardAction(null);
            if (res.accounting_pending) {
                addToast(`Saved "${editorTarget.name}"; storage accounting requires reconciliation`, 'info');
            } else {
                addToast(`Saved "${editorTarget.name}"`, 'success');
            }
            onRefresh();
        } catch (err) {
            if (sequence !== editorSeqRef.current) return;
            const msg = extractMcBrowserError(err, 'Failed to save file content.');
            setEditorError(msg);
            if (
                err instanceof McBrowserRequestError &&
                (err.status === 409 || err.status === 412 || /ETAG|CONFLICT|STALE|PRECONDITION/i.test(err.code))
            ) {
                setEditorStaleConflict(true);
            }
            addToast(msg, 'error');
        } finally {
            editorSaveInFlightRef.current = false;
            setEditorSaving(false);
        }
    };

    const resetEditorDialog = () => {
        if (editorSaveInFlightRef.current) return;
        editorSeqRef.current += 1;
        if (editorAbortRef.current) {
            editorAbortRef.current.abort();
        }
        setEditorTarget(null);
        setEditorContent('');
        setEditorSavedContent('');
        setEditorDiscardAction(null);
        setEditorEtag('');
        setEditorError(null);
        setEditorStaleConflict(false);
        setEditorLoading(false);
    };

    const closeEditorDialog = () => {
        if (editorSaveInFlightRef.current) return;
        if (editorDirty) {
            setEditorDiscardAction('close');
            return;
        }
        resetEditorDialog();
    };

    const reloadEditorContent = () => {
        if (!editorTarget || editorSaveInFlightRef.current) return;
        if (editorDirty) {
            setEditorDiscardAction('reload');
            return;
        }
        void loadFileIntoEditor(editorTarget);
    };

    const discardEditorChanges = () => {
        if (editorSaveInFlightRef.current) return;
        if (editorDiscardAction === 'reload' && editorTarget) {
            void loadFileIntoEditor(editorTarget);
        } else {
            resetEditorDialog();
        }
    };

    // File Info & Checksum Handlers
    const fetchEntryInfo = useCallback(
        async (entry: McBrowserEntry, algorithm: McBrowserChecksumAlgorithm) => {
            if (!permissions.read) {
                addToast('Inspecting file metadata is disabled by workspace policy.', 'error');
                return;
            }
            const targetKind = getMcBrowserEntryTargetKind(entry);
            if (targetKind !== 'file' && targetKind !== 'directory') {
                addToast('Metadata inspection requires a regular file or confined directory target.', 'info');
                return;
            }
            const seq = ++infoSeqRef.current;
            if (infoAbortRef.current) {
                infoAbortRef.current.abort();
            }
            const controller = new AbortController();
            infoAbortRef.current = controller;

            setInfoTarget(entry);
            setInfoChecksumAlg(algorithm);
            setInfoLoading(true);
            setInfoError(null);

            try {
                const res = await fetchMcBrowserFileInfo(entry.path, targetKind === 'directory' ? null : algorithm, controller.signal);
                if (seq !== infoSeqRef.current) return;
                setInfoData(res);
            } catch (err) {
                if (seq !== infoSeqRef.current) return;
                if (err instanceof Error && err.name === 'AbortError') return;
                setInfoError(extractMcBrowserError(err, 'Failed to compute file info and checksum.'));
            } finally {
                if (seq === infoSeqRef.current) {
                    setInfoLoading(false);
                }
            }
        },
        [addToast, permissions.read]
    );

    const closeInfoDialog = () => {
        if (infoAbortRef.current) {
            infoAbortRef.current.abort();
        }
        setInfoTarget(null);
        setInfoData(null);
        setInfoError(null);
        setInfoLoading(false);
    };

    // Batch Move / Copy / Delete Handlers
    const openBatchDialog = (mode: 'move' | 'copy' | 'delete', initialEntries?: McBrowserEntry[]) => {
        if (mode === 'move' && !permissions.rename) {
            addToast('Moving entries is disabled by workspace policy.', 'error');
            return;
        }
        if (mode === 'copy' && (!permissions.create || !permissions.read)) {
            addToast('Copying entries is disabled by workspace policy.', 'error');
            return;
        }
        if (mode === 'delete' && !permissions.delete) {
            addToast('Deleting entries is disabled by workspace policy.', 'error');
            return;
        }

        const candidateEntries = initialEntries && initialEntries.length > 0 ? initialEntries : selectedEntries;
        if (mode === 'copy' && candidateEntries.some((entry) => {
            const kind = getMcBrowserEntryTargetKind(entry);
            return kind !== 'file' && kind !== 'directory';
        })) {
            addToast('Broken aliases and special files cannot be copied.', 'info');
            return;
        }

        if (initialEntries && initialEntries.length > 0) {
            setSelectedPaths(initialEntries.filter((entry) => activeSourceEntries.some((visible) => visible.path === entry.path))
                .map((entry) => entry.path));
        } else if (selectedPaths.length === 0) {
            addToast('Select at least one entry first.', 'info');
            return;
        }

        setBatchMode(mode);
        setBatchTargets(candidateEntries.map((entry) => ({ ...entry })));
        setBatchFromClipboard(false);
        setBatchDestinationDir(currentPath);
        setBatchConflictPolicy('error');
        setBatchRecursiveDelete(true);
        setBatchError(null);
        setBatchOutcomes([]);
    };

    const handleExecuteBatch = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!batchMode) return;

        const targets = batchTargets;

        if ((batchMode === 'move' && !permissions.rename) ||
            (batchMode === 'copy' && (!permissions.create || !permissions.read)) ||
            (batchMode === 'delete' && !permissions.delete)) {
            setBatchError('This operation is disabled by current workspace policy.');
            return;
        }

        if (targets.length === 0) {
            setBatchError('No items selected for batch operation.');
            return;
        }

        let normalizedDestinationDir = '';
        if (batchMode === 'move' || batchMode === 'copy') {
            if (batchConflictPolicy === 'overwrite' && !permissions.modify) {
                setBatchError('Overwriting existing destination entries requires modify permission.');
                return;
            }
            try {
                normalizedDestinationDir = normalizeRelativePath(batchDestinationDir);
            } catch (err) {
                setBatchError(extractMcBrowserError(err, 'Destination directory must be a valid relative path.'));
                return;
            }
        }

        setBatchRunning(true);
        setBatchError(null);
        const outcomes: McBrowserBatchItemOutcome[] = [];
        const failedPaths: string[] = [];
        let succeededCount = 0;

        for (const item of targets) {
            if (batchMode === 'move' || batchMode === 'copy') {
                let destPath = '';
                try {
                    destPath = resolveBatchDestinationPath(item.path, batchDestinationDir, batchConflictPolicy);
                } catch (err) {
                    const classified = classifyBatchError(err);
                    outcomes.push({
                        path: item.path,
                        status: classified.status,
                        code: classified.code,
                        message: classified.message,
                    });
                    failedPaths.push(item.path);
                    continue;
                }

                try {
                    const res =
                        batchMode === 'move'
                            ? batchConflictPolicy === 'error'
                                ? await renameMcBrowserEntry(item.path, destPath)
                                : await renameMcBrowserEntry(item.path, destPath, batchConflictPolicy)
                            : batchConflictPolicy === 'error'
                            ? await copyMcBrowserEntry(item.path, destPath)
                            : await copyMcBrowserEntry(item.path, destPath, batchConflictPolicy);
                    const actualDest =
                        (res &&
                            typeof res === 'object' &&
                            ((typeof res.to === 'string' && res.to.trim()) ||
                                (typeof res.path === 'string' && res.path.trim()))) ||
                        destPath;
                    outcomes.push({
                        path: item.path,
                        destinationPath: actualDest,
                        status: 'success',
                        message: `${batchMode === 'move' ? 'Moved' : 'Copied'} to ${actualDest}${res?.accounting_pending ? '; storage accounting requires reconciliation' : ''}`,
                    });
                    succeededCount++;
                } catch (err) {
                    const classified = classifyBatchError(err);
                    outcomes.push({
                        path: item.path,
                        destinationPath: destPath,
                        status: classified.status,
                        code: classified.code,
                        message: classified.message,
                    });
                    failedPaths.push(item.path);
                }
            } else if (batchMode === 'delete') {
                try {
                    const res =
                        item.kind === 'directory' && batchRecursiveDelete
                            ? await deleteMcBrowserRecursive(item.path)
                            : await deleteMcBrowserEntry(item.path);
                    outcomes.push({
                        path: item.path,
                        status: 'success',
                        message: `Deleted permanently${res?.accounting_pending ? '; storage accounting requires reconciliation' : ''}`,
                    });
                    succeededCount++;
                } catch (err) {
                    const classified = classifyBatchError(err);
                    outcomes.push({
                        path: item.path,
                        status: classified.status,
                        code: classified.code,
                        message: classified.message,
                    });
                    failedPaths.push(item.path);
                }
            }
        }

        setBatchOutcomes(outcomes);
        setBatchRunning(false);

        // Preserve failed items in selection so they are never silently dropped or optimistically removed
        setSelectedPaths(batchFromClipboard
            ? failedPaths.filter((path) => activeSourceEntries.some((entry) => entry.path === path))
            : failedPaths);
        setBatchTargets(targets.filter((entry) => failedPaths.includes(entry.path)));
        if (batchFromClipboard && batchMode === 'move') {
            setClipboard((current) => current && current.mode === 'move'
                ? { ...current, entries: current.entries.filter((entry) => failedPaths.includes(entry.path)) }
                : current);
        }

        if (succeededCount > 0) {
            onRefresh();
        }

        if (failedPaths.length === 0) {
            addToast(
                `Batch ${batchMode} completed (${succeededCount} item${succeededCount === 1 ? '' : 's'}).`,
                'success'
            );
            if (
                (batchMode === 'move' || batchMode === 'copy') &&
                succeededCount > 0 &&
                preferences.redirect_after_copy_move
            ) {
                onNavigate(normalizedDestinationDir);
            }
        } else {
            addToast(
                `Batch ${batchMode} finished with partial errors: ${succeededCount} succeeded, ${failedPaths.length} failed.`,
                'error'
            );
        }
    };

    const closeBatchDialog = () => {
        if (batchRunning) return;
        setBatchMode(null);
        setBatchTargets([]);
        setBatchFromClipboard(false);
        setBatchConflictPolicy('error');
        setBatchError(null);
        setBatchOutcomes([]);
    };

    // Archive Download Handler
    const handleDownloadArchive = async () => {
        if (!permissions.download) {
            setArchiveError('Archive download is forbidden by workspace policy.');
            return;
        }
        if (selectedPaths.length === 0) {
            setArchiveError('Select at least one entry to download as an archive.');
            return;
        }
        if (hasUnsupportedArchiveEntries) {
            setArchiveError('Archive download requires regular files, directories, or confined aliases to them.');
            return;
        }

        if (archiveAbortRef.current) {
            archiveAbortRef.current.abort();
        }
        const controller = new AbortController();
        archiveAbortRef.current = controller;

        setArchiveDownloading(true);
        setArchiveError(null);
        setLastArchiveMessage(null);

        try {
            const result = await downloadMcBrowserArchive(selectedPaths, archiveFormat, {
                signal: controller.signal,
            });
            const summary =
                result.method === 'browser-navigation'
                    ? `Started browser download of "${result.filename}" without buffering the archive in memory.`
                    : result.method === 'filesystem-access'
                    ? `Streamed "${result.filename}" (${formatBytes(result.bytesWritten)}) directly to disk via File System Access.`
                    : `Downloaded "${result.filename}" (${formatBytes(result.bytesWritten)}) via bounded blob fallback (<= 128 MiB).`;
            setLastArchiveMessage(summary);
            addToast(summary, 'success');
        } catch (err) {
            if (err instanceof Error && err.name === 'AbortError') return;
            const msg = extractMcBrowserError(err, 'Failed to download archive.');
            setArchiveError(msg);
            addToast(msg, 'error');
        } finally {
            setArchiveDownloading(false);
        }
    };

    // Share Links Dialog Handlers
    const loadShares = useCallback(async () => {
        if (!permissions.share) {
            setSharesError('Sharing is disabled by workspace policy.');
            return;
        }
        if (sharesAbortRef.current) {
            sharesAbortRef.current.abort();
        }
        const controller = new AbortController();
        sharesAbortRef.current = controller;

        setSharesLoading(true);
        setSharesError(null);
        try {
            const res = await listMcBrowserShares(controller.signal);
            if (controller.signal.aborted) return;
            setSharesList(Array.isArray(res.shares) ? res.shares : []);
        } catch (err) {
            if (err instanceof Error && err.name === 'AbortError') return;
            setSharesError(extractMcBrowserError(err, 'Failed to load share links.'));
        } finally {
            if (!controller.signal.aborted) {
                setSharesLoading(false);
            }
        }
    }, [permissions.share]);

    const openSharesDialog = (defaultPath?: string) => {
        if (!permissions.share) {
            addToast('Share link management is disabled by workspace policy.', 'error');
            return;
        }
        const shareableSelectedPath = selectedEntries.find((entry) => {
            const targetKind = getMcBrowserEntryTargetKind(entry);
            return targetKind === 'file' || targetKind === 'directory';
        })?.path;
        const initialPath = defaultPath ?? shareableSelectedPath ?? currentPath;
        setShareTargetPath(initialPath);
        setSharePassword('');
        setShareExpiresAt('');
        setShareAllowDownload(true);
        setSharesOpen(true);
        void loadShares();
    };

    const renderAliasShareControl = (entry: McBrowserEntry) => {
        const targetKind = getMcBrowserEntryTargetKind(entry);
        if (entry.kind !== 'symlink' || (targetKind !== 'file' && targetKind !== 'directory')) return null;
        return (
            <button
                type="button"
                onClick={(event) => { event.stopPropagation(); openSharesDialog(entry.path); }}
                disabled={!permissions.share}
                aria-label={`Share ${entry.name}`}
                title="Share Link"
                className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-indigo-300 disabled:opacity-40"
            >
                <Share2 size={13} />
            </button>
        );
    };

    const handleCreateShareSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!permissions.share) {
            setSharesError('Creating shares is forbidden by workspace policy.');
            return;
        }
        setShareSubmitting(true);
        setSharesError(null);
        try {
            const res = await createMcBrowserShare({
                path: shareTargetPath,
                password: sharePassword || undefined,
                expires_at: shareExpiresAt || undefined,
                allow_download: shareAllowDownload,
            });
            if (res.share) {
                setSharesList((prev) => [res.share, ...prev.filter((s) => s.id !== res.share.id)]);
            }
            setSharePassword('');
            setShareExpiresAt('');
            addToast(`Created share link for "${res.share?.path || shareTargetPath}"`, 'success');
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to create share link.');
            setSharesError(msg);
            addToast(msg, 'error');
        } finally {
            setShareSubmitting(false);
        }
    };

    const handleRevokeShare = async (shareId: string) => {
        if (!permissions.share) {
            setSharesError('Revoking shares is forbidden by workspace policy.');
            return;
        }
        setRevokingShareId(shareId);
        setSharesError(null);
        try {
            await revokeMcBrowserShare(shareId);
            setSharesList((prev) => prev.filter((item) => item.id !== shareId));
            addToast('Revoked share link.', 'success');
        } catch (err) {
            const msg = extractMcBrowserError(err, 'Failed to revoke share link.');
            setSharesError(msg);
            addToast(msg, 'error');
        } finally {
            setRevokingShareId(null);
        }
    };

    const handleEntryPrimaryClick = (entry: McBrowserEntry) => {
        if (entry.kind === 'other') return;
        const targetKind = getMcBrowserEntryTargetKind(entry);
        if (targetKind === 'directory') {
            onNavigate(entry.path);
        } else if (targetKind === 'file') {
            void loadFileIntoEditor(entry);
        }
    };

    const pasteClipboard = () => {
        if (!clipboard || clipboard.entries.length === 0) return;
        if ((clipboard.mode === 'move' && !permissions.rename) ||
            (clipboard.mode === 'copy' && (!permissions.read || !permissions.create))) return;
        openBatchDialog(clipboard.mode, clipboard.entries);
        setBatchFromClipboard(true);
        setBatchConflictPolicy(clipboard.sourcePath === currentPath ? 'keep-both' : 'error');
    };

    const handleWorkspaceKeyDown = (event: React.KeyboardEvent<HTMLElement>) => {
        const target = event.target;
        if (event.defaultPrevented || event.nativeEvent.isComposing || event.altKey ||
            !(target instanceof Element) ||
            target.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"]), [role="textbox"], [role="dialog"], [aria-modal="true"]') ||
            editorTarget || newFileOpen || infoTarget || sharesOpen || batchMode || actionsOpen) return;

        const command = event.ctrlKey || event.metaKey;
        const key = event.key.toLowerCase();
        if (!command && event.key === 'Escape') {
            setSelectedPaths([]);
            event.preventDefault();
        } else if (!command && event.key === 'Delete' && permissions.delete && selectedEntries.length > 0) {
            openBatchDialog('delete');
            event.preventDefault();
        } else if (!command && event.key === 'F2' && permissions.rename && selectedEntries.length === 1 && onRename) {
            onRename(selectedEntries[0]);
            event.preventDefault();
        } else if (command && event.shiftKey && key === 'f' && permissions.read) {
            searchInputRef.current?.focus();
            event.preventDefault();
        } else if (command && !event.shiftKey && key === 'a') {
            setSelectedPaths((current) => Array.from(new Set([
                ...current, ...selectableVisibleEntries.map((entry) => entry.path),
            ])));
            event.preventDefault();
        } else if (command && !event.shiftKey && (key === 'c' || key === 'x') && selectedEntries.length > 0) {
            const mode = key === 'x' ? 'move' : 'copy';
            if ((mode === 'move' && !permissions.rename) ||
                (mode === 'copy' && (!permissions.read || !permissions.create || hasUnsupportedCopyEntries))) return;
            setClipboard({ mode, entries: selectedEntries.map((entry) => ({ ...entry })), sourcePath: currentPath });
            event.preventDefault();
        } else if (command && !event.shiftKey && key === 'v' && clipboard?.entries.length) {
            pasteClipboard();
            event.preventDefault();
        } else if (command && !event.shiftKey && key === 's' && permissions.download && selectedEntries.length > 0 && !hasUnsupportedArchiveEntries) {
            void handleDownloadArchive();
            event.preventDefault();
        }
    };

    const usagePercentage = useMemo(() => {
        if (!usage || !usage.quota_bytes || usage.quota_bytes <= 0) return null;
        return Math.min(100, Math.round((usage.used_bytes / usage.quota_bytes) * 100));
    }, [usage]);

    return (
        <section
            aria-label="Advanced file actions and workspace explorer"
            aria-describedby="mcbrowser-workspace-shortcuts"
            tabIndex={0}
            onKeyDown={handleWorkspaceKeyDown}
            className="space-y-4 rounded-2xl border border-indigo-500/20 bg-slate-900/50 backdrop-blur-xl p-5"
        >
            {/* Header & Policy/Usage Summary */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
                <div className="space-y-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                        <SlidersHorizontal size={16} className="text-indigo-400" />
                        <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                            Advanced File Actions &amp; Parity Workspace
                        </h3>
                        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                            Scope: {policy.scope || 'My files'}
                        </span>
                        {usage && (
                            <span
                                aria-label="Storage quota usage"
                                className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 flex items-center gap-1.5"
                            >
                                <HardDrive size={12} />
                                {formatBytes(usage.used_bytes)}
                                {usage.quota_bytes > 0 ? ` / ${formatBytes(usage.quota_bytes)}` : ''}
                                {usagePercentage !== null ? ` (${usagePercentage}%)` : ''} · {usage.status}
                            </span>
                        )}
                    </div>
                    <p className="text-xs text-slate-400">
                        Multi-select batch operations, optimistic ETag UTF-8 editor, recursive search, checksums, share links, and streaming archives.
                    </p>
                </div>

                {/* Primary Advanced Action Buttons */}
                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        aria-expanded={actionsOpen}
                        onClick={() => setActionsOpen((open) => !open)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-500/20 border border-indigo-500/40 text-indigo-200 hover:bg-indigo-500/30"
                    >
                        <Shield size={14} />
                        <span>Safe Built-In Actions</span>
                    </button>
                    <button
                        type="button"
                        onClick={openNewFileDialog}
                        disabled={!permissions.create}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-500/20 border border-indigo-500/40 text-indigo-200 hover:bg-indigo-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                        <FilePlus size={14} />
                        <span>New File</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => openSharesDialog()}
                        disabled={!permissions.share}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.05] border border-white/10 text-slate-200 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                        <Share2 size={14} className="text-indigo-400" />
                        <span>Share Links</span>
                    </button>

                    {/* View & Hidden Files Preferences */}
                    <div
                        role="group"
                        aria-label="Workspace view preferences"
                        className="flex flex-wrap items-center gap-1 bg-black/30 border border-white/10 rounded-xl p-1"
                    >
                        <button
                            type="button"
                            onClick={() => handleUpdatePreferences({ view: 'list' })}
                            aria-pressed={normalizedView === 'list'}
                            aria-label="List view"
                            className={`flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold transition-colors ${
                                normalizedView === 'list'
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <List size={13} />
                            <span>List</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => handleUpdatePreferences({ view: 'grid' })}
                            aria-pressed={normalizedView === 'grid'}
                            aria-label="Grid view"
                            className={`flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold transition-colors ${
                                normalizedView === 'grid'
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <LayoutGrid size={13} />
                            <span>Grid</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => handleUpdatePreferences({ view: 'gallery' })}
                            aria-pressed={normalizedView === 'gallery'}
                            aria-label="Gallery view"
                            className={`flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold transition-colors ${
                                normalizedView === 'gallery'
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <LayoutGrid size={13} />
                            <span>Gallery</span>
                        </button>
                        <button
                            type="button"
                            onClick={() =>
                                handleUpdatePreferences({ show_hidden: !preferences.show_hidden })
                            }
                            aria-pressed={preferences.show_hidden}
                            aria-label="Toggle hidden files"
                            className={`flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold transition-colors ${
                                preferences.show_hidden
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            {preferences.show_hidden ? <Eye size={13} /> : <EyeOff size={13} />}
                            <span>Hidden</span>
                        </button>
                        <button
                            type="button"
                            onClick={() =>
                                handleUpdatePreferences({ single_click: !preferences.single_click })
                            }
                            aria-pressed={preferences.single_click}
                            aria-label="Toggle single click open"
                            className={`px-2 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                                preferences.single_click
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            1-Click
                        </button>
                        <button
                            type="button"
                            onClick={() =>
                                handleUpdatePreferences({
                                    natural_sort: preferences.natural_sort === false,
                                })
                            }
                            aria-pressed={preferences.natural_sort !== false}
                            aria-label="Toggle natural sort"
                            className={`px-2 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                                preferences.natural_sort !== false
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Natural
                        </button>
                        <button
                            type="button"
                            onClick={() =>
                                handleUpdatePreferences({
                                    redirect_after_copy_move: !preferences.redirect_after_copy_move,
                                })
                            }
                            aria-pressed={Boolean(preferences.redirect_after_copy_move)}
                            aria-label="Toggle redirect after copy or move"
                            className={`px-2 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                                preferences.redirect_after_copy_move
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Redirect
                        </button>
                        <button
                            type="button"
                            onClick={() =>
                                handleUpdatePreferences({ date_format: !preferences.date_format })
                            }
                            aria-pressed={Boolean(preferences.date_format)}
                            aria-label="Toggle exact date format"
                            className={`px-2 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                                preferences.date_format
                                    ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            Exact Date
                        </button>
                        <select
                            aria-label="Workspace locale"
                            value={preferences.locale || 'en-US'}
                            onChange={(e) =>
                                void handleUpdatePreferences({ locale: e.target.value })
                            }
                            className="px-2 py-1 rounded-lg bg-black/50 border border-white/10 text-[11px] text-slate-200 focus:outline-none focus:border-indigo-500"
                        >
                            {LOCALE_OPTIONS.map((loc) => (
                                <option key={loc} value={loc} className="bg-slate-900">
                                    {loc}
                                </option>
                            ))}
                        </select>
                        {prefsSaving && (
                            <Loader2
                                size={12}
                                aria-label="Saving preferences"
                                className="animate-spin text-indigo-400 mx-1"
                            />
                        )}
                    </div>
                </div>
            </div>

            {/* Policy Permission Badges & Metadata Notice */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                <div className="flex flex-wrap items-center gap-1.5" aria-label="Active policy permissions">
                    <Shield size={13} className="text-indigo-400" />
                    <span>Policy permissions:</span>
                    {(
                        Object.entries(permissions) as Array<[keyof McBrowserPolicyPermissions, boolean]>
                    ).map(([permKey, allowed]) => (
                        <span
                            key={permKey}
                            className={`px-2 py-0.5 rounded-md font-mono uppercase border ${
                                allowed
                                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                                    : 'bg-rose-500/15 text-rose-300 border-rose-500/30 line-through'
                            }`}
                        >
                            {permKey}:{allowed ? 'allow' : 'deny'}
                        </span>
                    ))}
                </div>
                {(metaError || usageError) && (
                    <span role="status" className="text-amber-300">
                        Metadata notice: {[metaError, usageError].filter(Boolean).join(' · ')}
                    </span>
                )}
            </div>

            {/* Recursive Server Search Bar */}
            <form
                onSubmit={handleSearchSubmit}
                aria-label="Recursive server search"
                className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 bg-black/30 p-3 rounded-xl border border-white/[0.06]"
            >
                <div className="relative flex-1">
                    {searchAiMode ? (
                        <Sparkles
                            size={14}
                            className="absolute left-3 top-1/2 -translate-y-1/2 text-indigo-400 pointer-events-none"
                        />
                    ) : (
                        <Search
                            size={14}
                            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none"
                        />
                    )}
                    <input
                        type="search"
                        value={searchQuery}
                        onChange={(e) => {
                            setSearchQuery(e.target.value);
                            if (searchError) setSearchError(null);
                        }}
                        disabled={!permissions.read}
                        placeholder={
                            searchAiMode
                                ? currentPath
                                    ? `FlowAI natural language search inside ${currentPath} (e.g. "The Pitt", "large mkv episodes")...`
                                    : 'FlowAI natural language file search across My files (e.g. "The Pitt", "spreadsheets about gas prices")...'
                                : currentPath
                                ? `Recursive server search inside ${currentPath}...`
                                : 'Recursive server search across My files...'
                        }
                        aria-label="Recursive search query"
                        ref={searchInputRef}
                        className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-black/50 border border-white/10 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                    />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        onClick={() => setSearchAiMode((prev) => !prev)}
                        aria-pressed={searchAiMode}
                        aria-label="Toggle FlowAI natural language search"
                        title="Pair file search with FlowAI for natural language queries"
                        className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-colors ${
                            searchAiMode
                                ? 'bg-indigo-500/20 text-indigo-200 border-indigo-500/40'
                                : 'bg-black/40 text-slate-400 border-white/10 hover:text-slate-200'
                        }`}
                    >
                        <Sparkles size={13} className={searchAiMode ? 'text-indigo-400' : 'text-slate-500'} />
                        <span>FlowAI</span>
                    </button>

                    <label htmlFor="mcbrowser-search-type" className="sr-only">
                        Search entry type
                    </label>
                    <select
                        id="mcbrowser-search-type"
                        aria-label="Search entry type"
                        value={searchType}
                        onChange={(e) => setSearchType(e.target.value as McBrowserSearchType)}
                        disabled={!permissions.read}
                        className="px-2.5 py-1.5 rounded-xl bg-black/50 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                        <option value="all">All types</option>
                        <option value="file">Files only</option>
                        <option value="directory">Folders only</option>
                    </select>

                    <button
                        type="submit"
                        disabled={!permissions.read || searchLoading}
                        className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-40 transition-colors"
                    >
                        {searchLoading ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />}
                        <span>Search Server</span>
                    </button>

                    {searchResults !== null && (
                        <button
                            type="button"
                            onClick={handleClearSearch}
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-white/10 text-slate-200 hover:bg-white/15 transition-colors"
                        >
                            <X size={13} />
                            <span>Clear Search</span>
                        </button>
                    )}
                </div>
            </form>

            {actionsOpen && (
                <McBrowserActions
                    currentPath={currentPath}
                    selectedPaths={selectedPaths}
                    selectedEntries={selectedEntries}
                    permissions={permissions}
                    onRefresh={onRefresh}
                    onNavigate={onNavigate}
                    onClose={() => setActionsOpen(false)}
                />
            )}

            {searchError && (
                <div
                    role="alert"
                    className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                >
                    {searchError}
                </div>
            )}

            {searchResults !== null && (
                <div
                    role="status"
                    aria-live="polite"
                    className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-xs text-indigo-200"
                >
                    <div className="flex flex-wrap items-center gap-2">
                        <span>
                            Showing {searchResults.length} recursive search result
                            {searchResults.length === 1 ? '' : 's'} for &ldquo;{searchQuery.trim()}&rdquo; (type:{' '}
                            {searchType}).
                        </span>
                        {searchAiInterpretation && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-indigo-500/20 border border-indigo-400/30 text-[11px] text-indigo-100">
                                <Sparkles size={11} className="text-indigo-300" />
                                <span>{searchAiInterpretation}</span>
                            </span>
                        )}
                    </div>
                    {searchTruncated && (
                        <span className="font-semibold text-amber-300">
                            Results truncated by server limit — refine your query for narrower matches.
                        </span>
                    )}
                </div>
            )}

            {/* Multi-select & Batch Action Bar */}
            <p id="mcbrowser-workspace-shortcuts" className="text-xs text-slate-400">
                Explorer shortcuts: Ctrl/⌘ A select all · Shift-click select range · Escape clear ·
                Ctrl/⌘ C copy · X cut · V paste · Shift F search · S download · Delete confirm deletion
                {onRename ? ' · F2 rename' : ''}. Shortcuts do not run inside text fields or dialogs.
            </p>
            {clipboard && clipboard.entries.length > 0 && (
                <div role="status" className="flex flex-wrap items-center gap-3 text-xs text-slate-300">
                    <span>{clipboard.entries.length} item(s) ready to {clipboard.mode === 'move' ? 'move' : 'copy'}.</span>
                    <button type="button" onClick={pasteClipboard}
                        disabled={clipboard.mode === 'move' ? !permissions.rename : !permissions.read || !permissions.create}
                        className="rounded-lg border border-white/20 px-3 py-1 disabled:opacity-40">
                        Paste into current folder
                    </button>
                    <button type="button" onClick={() => setClipboard(null)} className="underline">
                        Clear clipboard
                    </button>
                </div>
            )}
            <div
                role="region"
                aria-label="Multi-select batch actions"
                className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-black/30 border border-white/[0.06]"
            >
                <div className="flex flex-wrap items-center gap-2.5">
                    <button
                        type="button"
                        onClick={toggleSelectAllVisible}
                        disabled={selectableVisibleEntries.length === 0}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-white/[0.06] border border-white/10 text-slate-200 hover:bg-white/10 disabled:opacity-40"
                    >
                        {selectableVisibleEntries.length > 0 &&
                        selectableVisibleEntries.every((e) => selectedPaths.includes(e.path)) ? (
                            <CheckSquare size={14} className="text-indigo-400" />
                        ) : (
                            <Square size={14} className="text-slate-400" />
                        )}
                        <span>Select All ({selectableVisibleEntries.length})</span>
                    </button>

                    {selectedPaths.length > 0 && (
                        <button
                            type="button"
                            onClick={() => setSelectedPaths([])}
                            className="px-2 py-1 rounded-lg text-xs text-slate-400 hover:text-white"
                        >
                            Clear ({selectedPaths.length} selected)
                        </button>
                    )}

                    {/* Sort controls synced with preferences */}
                    <div className="flex items-center gap-1 ml-1">
                        <span className="text-[11px] text-slate-500">Sort:</span>
                        {(['name', 'size', 'modified'] as McBrowserSortField[]).map((field) => {
                            const isCurrent = preferences.sort === field;
                            return (
                                <button
                                    key={field}
                                    type="button"
                                    onClick={() => {
                                        const nextDir: McBrowserSortDirection =
                                            isCurrent && preferences.direction === 'asc' ? 'desc' : 'asc';
                                        void handleUpdatePreferences({ sort: field, direction: nextDir });
                                    }}
                                    aria-label={`Workspace sort by ${field}`}
                                    className={`px-2 py-0.5 rounded-md text-[11px] font-semibold capitalize ${
                                        isCurrent
                                            ? 'bg-indigo-500/25 text-indigo-200 border border-indigo-500/30'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {field} {isCurrent ? (preferences.direction === 'asc' ? '↑' : '↓') : ''}
                                </button>
                            );
                        })}
                    </div>
                </div>

                {/* Batch Action Triggers */}
                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        onClick={() => openBatchDialog('move')}
                        disabled={selectedPaths.length === 0 || !permissions.rename}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-white/[0.06] border border-white/10 text-slate-200 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Move size={13} className="text-indigo-400" />
                        <span>Batch Move</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => openBatchDialog('copy')}
                        disabled={selectedPaths.length === 0 || !permissions.read || !permissions.create || hasUnsupportedCopyEntries}
                        title={
                            hasUnsupportedCopyEntries
                                ? 'Broken aliases and special files cannot be copied; use Batch Move or Batch Delete for leaf symlinks.'
                                : undefined
                        }
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-white/[0.06] border border-white/10 text-slate-200 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Copy size={13} className="text-emerald-400" />
                        <span>Batch Copy</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => openBatchDialog('delete')}
                        disabled={selectedPaths.length === 0 || !permissions.delete}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-rose-500/15 border border-rose-500/30 text-rose-300 hover:bg-rose-500/25 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Trash2 size={13} />
                        <span>Batch Delete</span>
                    </button>

                    {/* Archive Download Selector */}
                    <div className="flex items-center gap-1 bg-black/40 border border-white/10 rounded-lg px-2 py-0.5">
                        <label htmlFor="mcbrowser-archive-format" className="sr-only">
                            Archive format
                        </label>
                        <select
                            id="mcbrowser-archive-format"
                            aria-label="Archive format"
                            value={archiveFormat}
                            onChange={(e) => setArchiveFormat(e.target.value as McBrowserArchiveFormat)}
                            disabled={!permissions.download || archiveDownloading || hasUnsupportedArchiveEntries}
                            className="bg-transparent text-xs text-slate-200 focus:outline-none"
                        >
                            <option value="zip" className="bg-slate-900">
                                ZIP
                            </option>
                            <option value="tar" className="bg-slate-900">
                                TAR
                            </option>
                            <option value="tar.gz" className="bg-slate-900">
                                TAR.GZ
                            </option>
                            <option value="tarbz2" className="bg-slate-900">TAR.BZ2</option>
                            <option value="tarxz" className="bg-slate-900">TAR.XZ</option>
                            <option value="tarlz4" className="bg-slate-900">TAR.LZ4</option>
                            <option value="tarsz" className="bg-slate-900">TAR.SZ</option>
                            <option value="tarbr" className="bg-slate-900">TAR.BR</option>
                            <option value="tarzst" className="bg-slate-900">TAR.ZST</option>
                        </select>
                        <button
                            type="button"
                            onClick={handleDownloadArchive}
                            disabled={
                                selectedPaths.length === 0 ||
                                !permissions.download ||
                                archiveDownloading ||
                                hasUnsupportedArchiveEntries
                            }
                            title={
                                hasUnsupportedArchiveEntries
                                    ? 'Broken aliases and special files cannot be archived.'
                                    : undefined
                            }
                            className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold text-emerald-300 hover:bg-emerald-500/15 disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            {archiveDownloading ? (
                                <Loader2 size={13} className="animate-spin" />
                            ) : (
                                <Archive size={13} />
                            )}
                            <span>Download Archive</span>
                        </button>
                    </div>
                </div>
            </div>

            {archiveError && (
                <div
                    role="alert"
                    className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                >
                    {archiveError}
                </div>
            )}

            {lastArchiveMessage && (
                <div
                    role="status"
                    className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-xs text-emerald-200"
                >
                    {lastArchiveMessage}
                </div>
            )}

            {/* Entry Selection View (List vs Grid vs Gallery) */}
            {visibleEntries.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-400">
                    {searchResults !== null
                        ? 'No entries matched your recursive search criteria.'
                        : 'No entries to display in the parity workspace view.'}
                </div>
            ) : normalizedView === 'gallery' ? (
                <div
                    role="list"
                    aria-label="Workspace gallery entries"
                    className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
                >
                    {visibleEntries.map((entry) => {
                        const isSelected = selectedPaths.includes(entry.path);
                        const isUnsupported = entry.kind === 'other';
                        const isSymlink = entry.kind === 'symlink';
                        const targetKind = getMcBrowserEntryTargetKind(entry);
                        const isNavigableSymlinkDir = isSymlink && targetKind === 'directory';
                        const canPrimaryOpen = targetKind === 'file' || targetKind === 'directory';

                        return (
                            <div
                                key={entry.path}
                                role="listitem"
                                onClick={() => {
                                    if (preferences.single_click && canPrimaryOpen) {
                                        handleEntryPrimaryClick(entry);
                                    }
                                }}
                                className={`rounded-2xl border p-4 flex flex-col justify-between gap-4 transition-colors ${
                                    isSelected
                                        ? 'border-indigo-500/60 bg-indigo-500/15'
                                        : 'border-white/[0.08] bg-black/30 hover:bg-white/[0.04]'
                                }`}
                            >
                                <div className="h-24 rounded-xl bg-gradient-to-br from-indigo-500/10 via-slate-900/60 to-emerald-500/10 border border-white/[0.05] flex items-center justify-center">
                                    {targetKind === 'directory' ? (
                                        <Folder size={32} className="text-indigo-400" />
                                    ) : entry.kind === 'file' ? (
                                        <FileText size={32} className="text-emerald-400" />
                                    ) : (
                                        <FileQuestion size={32} className="text-amber-400" />
                                    )}
                                </div>
                                <div className="flex items-start justify-between gap-2">
                                    <div className="flex items-center gap-2.5 min-w-0">
                                        <input
                                            type="checkbox"
                                            checked={isSelected}
                                            disabled={isUnsupported}
                                            aria-label={`Select ${entry.name}`}
                                            onChange={(event) => toggleSelectPath(entry.path, 'shiftKey' in event.nativeEvent && event.nativeEvent.shiftKey === true)}
                                            onClick={(e) => e.stopPropagation()}
                                            className="rounded border-white/20 bg-black/50 text-indigo-500 focus:ring-indigo-500"
                                        />
                                        <div className="min-w-0">
                                            {!canPrimaryOpen ? (
                                                <span className="text-xs font-semibold text-slate-400 truncate block">
                                                    {isSymlink ? `${entry.name} (Symlink)` : entry.name}
                                                </span>
                                            ) : (
                                                <button
                                                    type="button"
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleEntryPrimaryClick(entry);
                                                    }}
                                                    className="text-xs font-semibold text-slate-100 hover:text-indigo-300 truncate block text-left"
                                                >
                                                    {isNavigableSymlinkDir
                                                        ? `${entry.name} (Directory alias)`
                                                        : entry.name}
                                                </button>
                                            )}
                                            <span className="text-[11px] font-mono text-slate-500 block truncate">
                                                {formatWorkspaceDate(entry.modified)}
                                            </span>
                                        </div>
                                    </div>
                                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400 shrink-0">
                                        {isNavigableSymlinkDir ? 'symlink → dir' : entry.kind}
                                    </span>
                                </div>

                                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-white/[0.05]">
                                    <span>
                                        {targetKind === 'directory' ? '—' : formatBytes(entry.size)}
                                    </span>
                                    {!isUnsupported && !isSymlink && (
                                        <div
                                            className="flex items-center gap-1"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            {entry.kind === 'file' && (
                                                <button
                                                    type="button"
                                                    onClick={() => loadFileIntoEditor(entry)}
                                                    disabled={!permissions.read}
                                                    aria-label={`Edit ${entry.name}`}
                                                    title="UTF-8 Editor"
                                                    className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-indigo-300 disabled:opacity-40"
                                                >
                                                    <Edit3 size={13} />
                                                </button>
                                            )}
                                            <button
                                                type="button"
                                                onClick={() => fetchEntryInfo(entry, 'sha256')}
                                                disabled={!permissions.read}
                                                aria-label={`Info for ${entry.name}`}
                                                title="File Info & Checksums"
                                                className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-emerald-300 disabled:opacity-40"
                                            >
                                                <Info size={13} />
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => openSharesDialog(entry.path)}
                                                disabled={!permissions.share}
                                                aria-label={`Share ${entry.name}`}
                                                title="Share Link"
                                                className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-indigo-300 disabled:opacity-40"
                                            >
                                                <Share2 size={13} />
                                            </button>
                                        </div>
                                    )}
                                    {renderAliasEditorControl(entry)}
                                    {renderAliasShareControl(entry)}
                                    {isSymlink && (targetKind === 'file' || targetKind === 'directory') && (
                                        <button
                                            type="button"
                                            onClick={(event) => { event.stopPropagation(); fetchEntryInfo(entry, 'sha256'); }}
                                            disabled={!permissions.read}
                                            aria-label={`Info for ${entry.name}`}
                                            className="p-1 rounded hover:bg-white/10 text-emerald-300 disabled:opacity-40"
                                        >
                                            <Info size={13} />
                                        </button>
                                    )}
                                    {isSymlink && targetKind !== 'file' && targetKind !== 'directory' && (
                                        <span className="text-[10px] font-mono text-amber-300/80">
                                            Editor / copy / archive / share pending
                                        </span>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            ) : normalizedView === 'grid' ? (
                <div
                    role="list"
                    aria-label="Workspace grid entries"
                    className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3"
                >
                    {visibleEntries.map((entry) => {
                        const isSelected = selectedPaths.includes(entry.path);
                        const isUnsupported = entry.kind === 'other';
                        const isSymlink = entry.kind === 'symlink';
                        const targetKind = getMcBrowserEntryTargetKind(entry);
                        const isNavigableSymlinkDir = isSymlink && targetKind === 'directory';
                        const canPrimaryOpen = targetKind === 'file' || targetKind === 'directory';

                        return (
                            <div
                                key={entry.path}
                                role="listitem"
                                onClick={() => {
                                    if (preferences.single_click && canPrimaryOpen) {
                                        handleEntryPrimaryClick(entry);
                                    }
                                }}
                                className={`rounded-xl border p-3.5 flex flex-col justify-between gap-3 transition-colors ${
                                    isSelected
                                        ? 'border-indigo-500/50 bg-indigo-500/15'
                                        : 'border-white/[0.06] bg-black/25 hover:bg-white/[0.04]'
                                }`}
                            >
                                <div className="flex items-start justify-between gap-2">
                                    <div className="flex items-center gap-2.5 min-w-0">
                                        <input
                                            type="checkbox"
                                            checked={isSelected}
                                            disabled={isUnsupported}
                                            aria-label={`Select ${entry.name}`}
                                            onChange={(event) => toggleSelectPath(entry.path, 'shiftKey' in event.nativeEvent && event.nativeEvent.shiftKey === true)}
                                            onClick={(e) => e.stopPropagation()}
                                            className="rounded border-white/20 bg-black/50 text-indigo-500 focus:ring-indigo-500"
                                        />
                                        <div className="min-w-0">
                                            {!canPrimaryOpen ? (
                                                <span className="text-xs font-semibold text-slate-400 truncate block">
                                                    {isSymlink ? `${entry.name} (Symlink)` : entry.name}
                                                </span>
                                            ) : (
                                                <button
                                                    type="button"
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleEntryPrimaryClick(entry);
                                                    }}
                                                    className="text-xs font-semibold text-slate-100 hover:text-indigo-300 truncate block text-left"
                                                >
                                                    {isNavigableSymlinkDir
                                                        ? `${entry.name} (Directory alias)`
                                                        : entry.name}
                                                </button>
                                            )}
                                            <span className="text-[11px] font-mono text-slate-500 block truncate">
                                                {entry.path}
                                            </span>
                                        </div>
                                    </div>
                                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400 shrink-0">
                                        {isNavigableSymlinkDir ? 'symlink → dir' : entry.kind}
                                    </span>
                                </div>

                                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-white/[0.05]">
                                    <span>
                                        {targetKind === 'directory' ? '—' : formatBytes(entry.size)}
                                    </span>
                                    {!isUnsupported && !isSymlink && (
                                        <div
                                            className="flex items-center gap-1"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            {entry.kind === 'file' && (
                                                <button
                                                    type="button"
                                                    onClick={() => loadFileIntoEditor(entry)}
                                                    disabled={!permissions.read}
                                                    aria-label={`Edit ${entry.name}`}
                                                    title="UTF-8 Editor"
                                                    className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-indigo-300 disabled:opacity-40"
                                                >
                                                    <Edit3 size={13} />
                                                </button>
                                            )}
                                            <button
                                                type="button"
                                                onClick={() => fetchEntryInfo(entry, 'sha256')}
                                                disabled={!permissions.read}
                                                aria-label={`Info for ${entry.name}`}
                                                title="File Info & Checksums"
                                                className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-emerald-300 disabled:opacity-40"
                                            >
                                                <Info size={13} />
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => openSharesDialog(entry.path)}
                                                disabled={!permissions.share}
                                                aria-label={`Share ${entry.name}`}
                                                title="Share Link"
                                                className="p-1 rounded hover:bg-white/10 text-slate-300 hover:text-indigo-300 disabled:opacity-40"
                                            >
                                                <Share2 size={13} />
                                            </button>
                                        </div>
                                    )}
                                    {renderAliasEditorControl(entry)}
                                    {renderAliasShareControl(entry)}
                                    {isSymlink && (targetKind === 'file' || targetKind === 'directory') && (
                                        <button
                                            type="button"
                                            onClick={(event) => { event.stopPropagation(); fetchEntryInfo(entry, 'sha256'); }}
                                            disabled={!permissions.read}
                                            aria-label={`Info for ${entry.name}`}
                                            className="p-1 rounded hover:bg-white/10 text-emerald-300 disabled:opacity-40"
                                        >
                                            <Info size={13} />
                                        </button>
                                    )}
                                    {isSymlink && targetKind !== 'file' && targetKind !== 'directory' && (
                                        <span className="text-[10px] font-mono text-amber-300/80">
                                            Editor / copy / archive / share pending
                                        </span>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            ) : (
                <div className="overflow-x-auto">
                    <table
                        aria-label="Workspace selection table"
                        className="w-full text-left border-collapse text-xs"
                    >
                        <thead>
                            <tr className="border-b border-white/[0.08] text-[11px] font-bold uppercase tracking-wider text-slate-400">
                                <th className="py-2 px-2.5 w-8">Select</th>
                                <th className="py-2 px-2.5">Entry / Relative Path</th>
                                <th className="py-2 px-2.5 hidden sm:table-cell">Kind</th>
                                <th className="py-2 px-2.5">Size</th>
                                <th className="py-2 px-2.5 hidden md:table-cell">Modified</th>
                                <th className="py-2 px-2.5 text-right">Workspace Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.04]">
                            {visibleEntries.map((entry) => {
                                const isSelected = selectedPaths.includes(entry.path);
                                const isUnsupported = entry.kind === 'other';
                                const isSymlink = entry.kind === 'symlink';
                                const targetKind = getMcBrowserEntryTargetKind(entry);
                                const isNavigableSymlinkDir = isSymlink && targetKind === 'directory';
                                const canPrimaryOpen = targetKind === 'file' || targetKind === 'directory';

                                return (
                                    <tr
                                        key={entry.path}
                                        aria-selected={isSelected}
                                        onClick={() => {
                                            if (preferences.single_click && canPrimaryOpen) {
                                                handleEntryPrimaryClick(entry);
                                            }
                                        }}
                                        className={`transition-colors ${
                                            isSelected ? 'bg-indigo-500/15' : 'hover:bg-white/[0.04]'
                                        }`}
                                    >
                                        <td
                                            className="py-2 px-2.5"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            <input
                                                type="checkbox"
                                                checked={isSelected}
                                                disabled={isUnsupported}
                                                aria-label={`Select ${entry.name}`}
                                                onChange={(event) => toggleSelectPath(entry.path, 'shiftKey' in event.nativeEvent && event.nativeEvent.shiftKey === true)}
                                                className="rounded border-white/20 bg-black/50 text-indigo-500 focus:ring-indigo-500"
                                            />
                                        </td>
                                        <td className="py-2 px-2.5">
                                            <div className="flex items-center gap-2.5 min-w-0">
                                                {targetKind === 'directory' ? (
                                                    <Folder size={15} className="text-indigo-400 shrink-0" />
                                                ) : entry.kind === 'file' ? (
                                                    <FileText size={15} className="text-emerald-400 shrink-0" />
                                                ) : (
                                                    <FileQuestion size={15} className="text-amber-400 shrink-0" />
                                                )}
                                                <div className="min-w-0">
                                                    {isUnsupported ? (
                                                        <span className="font-medium text-slate-400">
                                                            {entry.name} (Unsupported {entry.kind})
                                                        </span>
                                                    ) : isSymlink && targetKind !== 'file' && !isNavigableSymlinkDir ? (
                                                        <span className="font-medium text-slate-300">
                                                            {`${entry.name} (Symlink — move/delete link only; editor/copy/archive/share pending)`}
                                                        </span>
                                                    ) : (
                                                        <button
                                                            type="button"
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                handleEntryPrimaryClick(entry);
                                                            }}
                                                            className="font-medium text-slate-100 hover:text-indigo-300 text-left truncate block"
                                                        >
                                                            {isNavigableSymlinkDir
                                                                ? `${entry.name} (Directory alias)`
                                                                : entry.name}
                                                        </button>
                                                    )}
                                                    {searchResults !== null && (
                                                        <span className="text-[11px] font-mono text-slate-500 block">
                                                            {entry.path}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="py-2 px-2.5 hidden sm:table-cell font-mono text-slate-400 capitalize">
                                            {isNavigableSymlinkDir ? 'symlink (dir)' : entry.kind}
                                        </td>
                                        <td className="py-2 px-2.5 font-mono text-slate-300 whitespace-nowrap">
                                            {targetKind === 'directory' ? '—' : formatBytes(entry.size)}
                                        </td>
                                        <td className="py-2 px-2.5 hidden md:table-cell text-slate-400 whitespace-nowrap">
                                            {formatWorkspaceDate(entry.modified)}
                                        </td>
                                        <td
                                            className="py-2 px-2.5 text-right whitespace-nowrap"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            {!isUnsupported && !isSymlink && (
                                                <div className="inline-flex items-center gap-1">
                                                    {entry.kind === 'file' && (
                                                        <button
                                                            type="button"
                                                            onClick={() => loadFileIntoEditor(entry)}
                                                            disabled={!permissions.read}
                                                            aria-label={`Edit ${entry.name}`}
                                                            className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-slate-200 disabled:opacity-40"
                                                        >
                                                            Edit UTF-8
                                                        </button>
                                                    )}
                                                    <button
                                                        type="button"
                                                        onClick={() => fetchEntryInfo(entry, 'sha256')}
                                                        disabled={!permissions.read}
                                                        aria-label={`Info for ${entry.name}`}
                                                        className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-slate-200 disabled:opacity-40"
                                                    >
                                                        Info / Hash
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => openSharesDialog(entry.path)}
                                                        disabled={!permissions.share}
                                                        aria-label={`Share ${entry.name}`}
                                                        className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-indigo-300 disabled:opacity-40"
                                                    >
                                                        Share
                                                    </button>
                                                </div>
                                            )}
                                            {renderAliasEditorControl(entry)}
                                            {renderAliasShareControl(entry)}
                                            {isSymlink && (targetKind === 'file' || targetKind === 'directory') && (
                                                <button
                                                    type="button"
                                                    onClick={() => fetchEntryInfo(entry, 'sha256')}
                                                    disabled={!permissions.read}
                                                    aria-label={`Info for ${entry.name}`}
                                                    className="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/10 text-emerald-300 disabled:opacity-40"
                                                >
                                                    Info / Hash
                                                </button>
                                            )}
                                            {isSymlink && targetKind !== 'file' && targetKind !== 'directory' && (
                                                <span className="text-[11px] font-mono text-amber-300/80">
                                                    Editor / copy / archive / share pending
                                                </span>
                                            )}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}

            {/* 1. New File Dialog */}
            {newFileOpen && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
                    onClick={() => !newFileBusy && setNewFileOpen(false)}
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="mcbrowser-new-file-title"
                        className="w-full max-w-lg rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 shadow-2xl space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between">
                            <h3
                                id="mcbrowser-new-file-title"
                                className="text-base font-bold text-slate-100 flex items-center gap-2"
                            >
                                <FilePlus size={18} className="text-indigo-400" />
                                <span>Create New UTF-8 File</span>
                            </h3>
                            <button
                                type="button"
                                onClick={() => setNewFileOpen(false)}
                                disabled={newFileBusy}
                                aria-label="Close new file dialog"
                                className="p-1 rounded-lg text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <form onSubmit={handleCreateFileSubmit} className="space-y-4">
                            <div>
                                <label
                                    htmlFor="mcbrowser-new-file-name"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    File Name
                                </label>
                                <input
                                    id="mcbrowser-new-file-name"
                                    type="text"
                                    value={newFileName}
                                    onChange={(e) => {
                                        setNewFileName(e.target.value);
                                        if (newFileError) setNewFileError(null);
                                    }}
                                    placeholder="e.g. server.properties"
                                    disabled={newFileBusy}
                                    className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/15 text-sm text-slate-100"
                                />
                                <p className="text-[11px] text-slate-400 mt-1">
                                    Target directory:{' '}
                                    <span className="font-mono text-slate-200">
                                        {currentPath ? `My files/${currentPath}` : 'My files'}
                                    </span>
                                </p>
                            </div>

                            <div>
                                <label
                                    htmlFor="mcbrowser-new-file-content"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Initial UTF-8 Content (optional)
                                </label>
                                <textarea
                                    id="mcbrowser-new-file-content"
                                    rows={6}
                                    value={newFileContent}
                                    onChange={(e) => setNewFileContent(e.target.value)}
                                    disabled={newFileBusy}
                                    className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/15 text-xs font-mono text-slate-100"
                                />
                            </div>

                            {newFileError && (
                                <div
                                    role="alert"
                                    className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                                >
                                    {newFileError}
                                </div>
                            )}

                            <div className="flex items-center justify-end gap-2">
                                <button
                                    type="button"
                                    onClick={() => setNewFileOpen(false)}
                                    disabled={newFileBusy}
                                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={newFileBusy}
                                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white disabled:opacity-50"
                                >
                                    {newFileBusy && <Loader2 size={14} className="animate-spin" />}
                                    <span>Create File</span>
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* 2. UTF-8 Editor Dialog with Optimistic ETag Concurrency */}
            {editorTarget && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
                    onClick={() => !editorSaving && closeEditorDialog()}
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="mcbrowser-editor-title"
                        className="w-full max-w-3xl rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 shadow-2xl space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between gap-3">
                            <div>
                                <h3
                                    id="mcbrowser-editor-title"
                                    className="text-base font-bold text-slate-100 flex items-center gap-2"
                                >
                                    <Edit3 size={18} className="text-indigo-400" />
                                    <span>UTF-8 Editor: {editorTarget.name}</span>
                                </h3>
                                <p className="text-xs font-mono text-slate-400 mt-0.5">
                                    Path: {editorTarget.path} · ETag: {editorEtag || 'loading...'}
                                </p>
                                {editorTarget.kind === 'symlink' && (
                                    <p role="note" className="text-xs text-amber-200 mt-1">
                                        Saving updates the confined file target. The alias itself is preserved.
                                    </p>
                                )}
                            </div>
                            <div className="flex items-center gap-2">
                                <label htmlFor="mcbrowser-editor-theme" className="text-xs text-slate-400">
                                    Theme:
                                </label>
                                <select
                                    id="mcbrowser-editor-theme"
                                    aria-label="Editor theme"
                                    value={preferences.editor_theme || 'chrome'}
                                    onChange={(e) =>
                                        void handleUpdatePreferences({ editor_theme: e.target.value })
                                    }
                                    className="px-2 py-1 rounded-lg bg-black/50 border border-white/15 text-xs font-mono text-slate-100"
                                >
                                    {EDITOR_THEME_OPTIONS.map((themeOpt) => (
                                        <option key={themeOpt} value={themeOpt} className="bg-slate-900">
                                            {themeOpt}
                                        </option>
                                    ))}
                                </select>
                                <button
                                    type="button"
                                    onClick={closeEditorDialog}
                                    disabled={editorSaving}
                                    aria-label="Close editor dialog"
                                    className="p-1 rounded-lg text-slate-400 hover:text-white"
                                >
                                    <X size={16} />
                                </button>
                            </div>
                        </div>

                        {editorLoading ? (
                            <div
                                role="status"
                                className="py-12 flex flex-col items-center justify-center gap-2 text-xs text-slate-400"
                            >
                                <Loader2 size={24} className="animate-spin text-indigo-400" />
                                <span>Loading file content and ETag...</span>
                            </div>
                        ) : (
                            <form onSubmit={handleSaveEditorContent} className="space-y-4">
                                <McBrowserCodeEditor
                                    key={editorTarget.path}
                                    path={editorTarget.path}
                                    value={editorContent}
                                    onChange={setEditorContent}
                                    readOnly={!permissions.modify || editorSaving || !editorEtag}
                                    theme={preferences.editor_theme || 'chrome'}
                                    onSave={() => void handleSaveEditorContent()}
                                />

                                {editorDiscardAction && (
                                    <div role="alert" className="space-y-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                                        <p>Unsaved changes will be lost. Discard them?</p>
                                        <div className="flex gap-3">
                                            <button type="button" onClick={() => setEditorDiscardAction(null)}>
                                                Keep editing
                                            </button>
                                            <button type="button" onClick={discardEditorChanges}>
                                                Discard changes
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {editorError && (
                                    <div
                                        role="alert"
                                        className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 space-y-2"
                                    >
                                        <p>{editorError}</p>
                                        {editorStaleConflict && (
                                            <div className="flex items-center gap-2">
                                                <span className="text-amber-300 font-semibold">
                                                    Stale ETag detected — file was modified on server.
                                                </span>
                                                <button
                                                    type="button"
                                                    onClick={reloadEditorContent}
                                                    className="px-2.5 py-1 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-200 font-semibold"
                                                >
                                                    Reload Latest Server Version
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                )}

                                <div className="flex items-center justify-between pt-2">
                                    <button
                                        type="button"
                                        onClick={reloadEditorContent}
                                        disabled={editorSaving}
                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/5 text-slate-300 hover:bg-white/10"
                                    >
                                        <RefreshCw size={13} />
                                        <span>Reload from Server</span>
                                    </button>

                                    <div className="flex items-center gap-2">
                                        <button
                                            type="button"
                                            onClick={closeEditorDialog}
                                            disabled={editorSaving}
                                            className="px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300"
                                        >
                                            Close
                                        </button>
                                        <button
                                            type="submit"
                                            disabled={!permissions.modify || editorSaving || !editorEtag}
                                            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-40"
                                        >
                                            {editorSaving ? (
                                                <Loader2 size={14} className="animate-spin" />
                                            ) : (
                                                <Save size={14} />
                                            )}
                                            <span>Save with ETag</span>
                                        </button>
                                    </div>
                                </div>
                            </form>
                        )}
                    </div>
                </div>
            )}

            {/* 3. File Info & Checksums Dialog */}
            {infoTarget && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
                    onClick={closeInfoDialog}
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="mcbrowser-info-title"
                        className="w-full max-w-lg rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 shadow-2xl space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between">
                            <h3
                                id="mcbrowser-info-title"
                                className="text-base font-bold text-slate-100 flex items-center gap-2"
                            >
                                <Info size={18} className="text-emerald-400" />
                                <span>Entry Info &amp; Checksums: {infoTarget.name}</span>
                            </h3>
                            <button
                                type="button"
                                onClick={closeInfoDialog}
                                aria-label="Close file info dialog"
                                className="p-1 rounded-lg text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        {getMcBrowserEntryTargetKind(infoTarget) === 'file' && <div className="flex items-center gap-2">
                            <label
                                htmlFor="mcbrowser-checksum-select"
                                className="text-xs font-semibold text-slate-300"
                            >
                                Checksum Algorithm:
                            </label>
                            <select
                                id="mcbrowser-checksum-select"
                                aria-label="Checksum Algorithm"
                                value={infoChecksumAlg}
                                onChange={(e) =>
                                    fetchEntryInfo(
                                        infoTarget,
                                        e.target.value as McBrowserChecksumAlgorithm
                                    )
                                }
                                disabled={infoLoading}
                                className="px-2.5 py-1 rounded-lg bg-black/50 border border-white/15 text-xs text-slate-100 uppercase font-mono"
                            >
                                <option value="sha256">sha256</option>
                                <option value="md5">md5</option>
                                <option value="sha1">sha1</option>
                                <option value="sha512">sha512</option>
                            </select>
                        </div>}

                        {infoLoading ? (
                            <div
                                role="status"
                                className="py-8 flex items-center justify-center gap-2 text-xs text-slate-400"
                            >
                                <Loader2 size={18} className="animate-spin text-indigo-400" />
                                <span>{getMcBrowserEntryTargetKind(infoTarget) === 'directory' ? 'Loading directory metadata...' : `Computing ${infoChecksumAlg.toUpperCase()} checksum...`}</span>
                            </div>
                        ) : infoError ? (
                            <div
                                role="alert"
                                className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                            >
                                {infoError}
                            </div>
                        ) : (
                            infoData && (
                                <div className="space-y-3 text-xs bg-black/40 p-4 rounded-xl border border-white/10">
                                    <div className="grid grid-cols-3 gap-2">
                                        <span className="text-slate-400">Path:</span>
                                        <span className="col-span-2 font-mono text-slate-100 break-all">
                                            {infoData.entry.path}
                                        </span>
                                        <span className="text-slate-400">Kind:</span>
                                        <span className="col-span-2 font-mono text-slate-200">
                                            {infoData.entry.kind}
                                        </span>
                                        {infoData.entry.kind === 'directory' && <>
                                            <span className="text-slate-400">Visible files:</span>
                                            <span className="col-span-2">{infoData.num_files ?? 'Unavailable'}</span>
                                            <span className="text-slate-400">Visible directories:</span>
                                            <span className="col-span-2">{infoData.num_dirs ?? 'Unavailable'}</span>
                                        </>}
                                        <span className="text-slate-400">Size:</span>
                                        <span className="col-span-2 font-mono text-slate-200">
                                            {formatBytes(infoData.entry.size)} ({infoData.entry.size} B)
                                        </span>
                                        <span className="text-slate-400">Modified:</span>
                                        <span className="col-span-2 text-slate-200">
                                            {formatWorkspaceDate(infoData.entry.modified)}
                                        </span>
                                    </div>
                                    <div className="pt-2 border-t border-white/10 space-y-1.5">
                                        <span className="text-slate-400 font-semibold block">
                                            Verified Digests:
                                        </span>
                                        {Object.entries(infoData.checksums || {}).map(([alg, digest]) => (
                                            <div key={alg} className="space-y-0.5">
                                                <span className="text-[10px] font-mono uppercase text-indigo-300">
                                                    {alg}:
                                                </span>
                                                <code className="block p-2 rounded bg-black/60 font-mono text-[11px] text-emerald-300 break-all">
                                                    {digest}
                                                </code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )
                        )}
                    </div>
                </div>
            )}

            {/* 4. Batch Move / Copy / Delete Confirmation & Per-Item Outcomes Dialog */}
            {batchMode && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
                    onClick={closeBatchDialog}
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="mcbrowser-batch-title"
                        className="w-full max-w-xl rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 shadow-2xl space-y-4"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between">
                            <h3
                                id="mcbrowser-batch-title"
                                className="text-base font-bold text-slate-100 capitalize flex items-center gap-2"
                            >
                                {batchMode === 'delete' ? (
                                    <Trash2 size={18} className="text-rose-400" />
                                ) : batchMode === 'move' ? (
                                    <Move size={18} className="text-indigo-400" />
                                ) : (
                                    <Copy size={18} className="text-emerald-400" />
                                )}
                                <span>Confirm Batch {batchMode}</span>
                            </h3>
                            <button
                                type="button"
                                onClick={closeBatchDialog}
                                disabled={batchRunning}
                                aria-label="Close batch dialog"
                                className="p-1 rounded-lg text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <form onSubmit={handleExecuteBatch} className="space-y-4">
                            <p className="text-xs text-slate-300">
                                {batchMode === 'delete'
                                    ? `Are you sure you want to delete ${batchTargets.length} selected item(s)? Items are only removed after server confirmation.`
                                    : `Specify the destination relative directory for ${batchTargets.length} selected item(s). Existing destination entries are never silently overwritten; server conflicts are reported per item.`}
                            </p>

                            {(batchMode === 'move' || batchMode === 'copy') && (
                                <div className="space-y-3">
                                    <div>
                                        <label
                                            htmlFor="mcbrowser-batch-destination"
                                            className="block text-xs font-semibold text-slate-300 mb-1"
                                        >
                                            Destination Relative Directory (empty for My files root)
                                        </label>
                                        <input
                                            id="mcbrowser-batch-destination"
                                            type="text"
                                            value={batchDestinationDir}
                                            onChange={(e) => {
                                                setBatchDestinationDir(e.target.value);
                                                if (batchError) setBatchError(null);
                                            }}
                                            placeholder="e.g. backups/archive"
                                            disabled={batchRunning}
                                            className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/15 text-xs font-mono text-slate-100"
                                        />
                                    </div>

                                    <div>
                                        <label
                                            htmlFor="mcbrowser-batch-conflict"
                                            className="block text-xs font-semibold text-slate-300 mb-1"
                                        >
                                            Conflict Resolution Policy
                                        </label>
                                        <select
                                            id="mcbrowser-batch-conflict"
                                            aria-label="Conflict Resolution Policy"
                                            value={batchConflictPolicy}
                                            onChange={(e) => {
                                                setBatchConflictPolicy(
                                                    e.target.value as McBrowserConflictPolicy
                                                );
                                                if (batchError) setBatchError(null);
                                            }}
                                            disabled={batchRunning}
                                            className="w-full px-3 py-2 rounded-xl bg-black/50 border border-white/15 text-xs text-slate-100"
                                        >
                                            <option value="error" className="bg-slate-900">
                                                Fail on conflict (default — keep existing, report conflict)
                                            </option>
                                            <option value="keep-both" className="bg-slate-900">
                                                Keep both (auto-rename destination as (1), (2), …)
                                            </option>
                                            <option
                                                value="overwrite"
                                                disabled={!permissions.modify}
                                                className="bg-slate-900"
                                            >
                                                Overwrite existing destination
                                                {!permissions.modify
                                                    ? ' (requires Modify permission)'
                                                    : ''}
                                            </option>
                                        </select>
                                    </div>

                                    {!permissions.modify && (
                                        <p className="text-[11px] text-amber-300/90">
                                            Overwrite is disabled because your account does not have{' '}
                                            <code>modify</code> permission.
                                        </p>
                                    )}

                                    {batchConflictPolicy === 'overwrite' && (
                                        <div
                                            role="note"
                                            aria-label="Overwrite conflict warning"
                                            className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200 flex items-start gap-2"
                                        >
                                            <AlertTriangle
                                                size={15}
                                                className="text-amber-400 shrink-0 mt-0.5"
                                            />
                                            <span>
                                                <strong>Overwrite Warning:</strong> Conflicting destination entries of the same kind will be permanently replaced and cannot be recovered.
                                            </span>
                                        </div>
                                    )}
                                </div>
                            )}

                            {batchMode === 'delete' && (
                                <label className="flex items-center gap-2 text-xs text-slate-200">
                                    <input
                                        type="checkbox"
                                        checked={batchRecursiveDelete}
                                        onChange={(e) => setBatchRecursiveDelete(e.target.checked)}
                                        disabled={batchRunning}
                                        className="rounded border-white/20 bg-black/50 text-rose-500"
                                    />
                                    <span>
                                        Use recursive delete (<code>POST /delete-recursive</code>) for selected directories
                                    </span>
                                </label>
                            )}

                            {batchError && (
                                <div
                                    role="alert"
                                    className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                                >
                                    {batchError}
                                </div>
                            )}

                            {batchOutcomes.length > 0 && (
                                <div
                                    role="region"
                                    aria-label="Batch operation outcomes"
                                    className="space-y-1.5 max-h-52 overflow-y-auto p-3 rounded-xl bg-black/40 border border-white/10"
                                >
                                    <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                                        Per-Item Batch Outcomes
                                    </p>
                                    {batchOutcomes.map((outcome) => (
                                        <div
                                            key={outcome.path}
                                            className="flex items-center justify-between gap-2 text-xs py-1 border-b border-white/[0.04] last:border-0"
                                        >
                                            <div className="flex items-center gap-2 min-w-0">
                                                {outcome.status === 'success' ? (
                                                    <CheckCircle2
                                                        size={14}
                                                        className="text-emerald-400 shrink-0"
                                                    />
                                                ) : outcome.status === 'conflict' ? (
                                                    <AlertTriangle
                                                        size={14}
                                                        className="text-amber-400 shrink-0"
                                                    />
                                                ) : (
                                                    <XCircle size={14} className="text-rose-400 shrink-0" />
                                                )}
                                                <span className="font-mono text-slate-200 truncate">
                                                    {outcome.path}
                                                </span>
                                            </div>
                                            <span
                                                className={`text-[11px] font-medium shrink-0 ${
                                                    outcome.status === 'success'
                                                        ? 'text-emerald-300'
                                                        : outcome.status === 'conflict'
                                                        ? 'text-amber-300'
                                                        : 'text-rose-300'
                                                }`}
                                            >
                                                {outcome.status.toUpperCase()}: {outcome.message}
                                                {outcome.code ? ` (${outcome.code})` : ''}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}

                            <div className="flex items-center justify-end gap-2 pt-2">
                                <button
                                    type="button"
                                    onClick={closeBatchDialog}
                                    disabled={batchRunning}
                                    className="px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300"
                                >
                                    Close
                                </button>
                                {batchTargets.length > 0 && (
                                    <button
                                        type="submit"
                                        disabled={
                                            batchRunning ||
                                            ((batchMode === 'move' || batchMode === 'copy') &&
                                                batchConflictPolicy === 'overwrite' &&
                                                !permissions.modify)
                                        }
                                        className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold text-white disabled:opacity-50 ${
                                            batchMode === 'delete'
                                                ? 'bg-rose-600 hover:bg-rose-500'
                                                : 'bg-indigo-600 hover:bg-indigo-500'
                                        }`}
                                    >
                                        {batchRunning && <Loader2 size={14} className="animate-spin" />}
                                        <span>
                                            Confirm Batch {batchMode.charAt(0).toUpperCase() + batchMode.slice(1)} (
                                            {batchTargets.length})
                                        </span>
                                    </button>
                                )}
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* 5. Share Links Management Dialog */}
            {sharesOpen && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
                    onClick={() => !shareSubmitting && setSharesOpen(false)}
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="mcbrowser-shares-title"
                        className="w-full max-w-2xl rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 shadow-2xl space-y-5"
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="flex items-center justify-between">
                            <h3
                                id="mcbrowser-shares-title"
                                className="text-base font-bold text-slate-100 flex items-center gap-2"
                            >
                                <Share2 size={18} className="text-indigo-400" />
                                <span>Manage Share Links</span>
                            </h3>
                            <button
                                type="button"
                                onClick={() => setSharesOpen(false)}
                                aria-label="Close share links dialog"
                                className="p-1 rounded-lg text-slate-400 hover:text-white"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <form
                            onSubmit={handleCreateShareSubmit}
                            className="space-y-3 p-4 rounded-xl bg-black/40 border border-white/10"
                        >
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                                Create New Share Link
                            </h4>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div className="sm:col-span-2">
                                    <label
                                        htmlFor="mcbrowser-share-path"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Relative Path to Share
                                    </label>
                                    <input
                                        id="mcbrowser-share-path"
                                        type="text"
                                        value={shareTargetPath}
                                        onChange={(e) => setShareTargetPath(e.target.value)}
                                        placeholder="e.g. configs/server.properties"
                                        disabled={shareSubmitting}
                                        className="w-full px-3 py-1.5 rounded-xl bg-black/50 border border-white/15 text-xs font-mono text-slate-100"
                                    />
                                </div>
                                <div>
                                    <label
                                        htmlFor="mcbrowser-share-password"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Password Protection (optional)
                                    </label>
                                    <input
                                        id="mcbrowser-share-password"
                                        type="password"
                                        value={sharePassword}
                                        onChange={(e) => setSharePassword(e.target.value)}
                                        placeholder="Optional share password"
                                        disabled={shareSubmitting}
                                        className="w-full px-3 py-1.5 rounded-xl bg-black/50 border border-white/15 text-xs text-slate-100"
                                    />
                                </div>
                                <div>
                                    <label
                                        htmlFor="mcbrowser-share-expires"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Expires At (ISO-8601 optional)
                                    </label>
                                    <input
                                        id="mcbrowser-share-expires"
                                        type="text"
                                        value={shareExpiresAt}
                                        onChange={(e) => setShareExpiresAt(e.target.value)}
                                        placeholder="e.g. 2026-12-31T23:59:59Z"
                                        disabled={shareSubmitting}
                                        className="w-full px-3 py-1.5 rounded-xl bg-black/50 border border-white/15 text-xs font-mono text-slate-100"
                                    />
                                </div>
                            </div>

                            <div className="flex items-center justify-between pt-1">
                                <label className="flex items-center gap-2 text-xs text-slate-200">
                                    <input
                                        type="checkbox"
                                        checked={shareAllowDownload}
                                        onChange={(e) => setShareAllowDownload(e.target.checked)}
                                        disabled={shareSubmitting}
                                        className="rounded border-white/20 bg-black/50 text-indigo-500"
                                    />
                                    <span>Allow recipients to download</span>
                                </label>

                                <button
                                    type="submit"
                                    disabled={shareSubmitting || !permissions.share}
                                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-40"
                                >
                                    {shareSubmitting ? (
                                        <Loader2 size={13} className="animate-spin" />
                                    ) : (
                                        <Link2 size={13} />
                                    )}
                                    <span>Create Share Link</span>
                                </button>
                            </div>
                        </form>

                        {sharesError && (
                            <div
                                role="alert"
                                className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300"
                            >
                                {sharesError}
                            </div>
                        )}

                        <div className="space-y-2">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                                Active Share Links ({sharesList.length})
                            </h4>
                            {sharesLoading ? (
                                <div
                                    role="status"
                                    className="py-6 flex items-center justify-center gap-2 text-xs text-slate-400"
                                >
                                    <Loader2 size={16} className="animate-spin text-indigo-400" />
                                    <span>Loading active share links...</span>
                                </div>
                            ) : sharesList.length === 0 ? (
                                <p className="text-xs text-slate-500 py-4 text-center">
                                    No active share links created yet.
                                </p>
                            ) : (
                                <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                                    {sharesList.map((share) => (
                                        <div
                                            key={share.id}
                                            className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-black/30 border border-white/[0.06] text-xs"
                                        >
                                            <div className="space-y-0.5 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <span className="font-mono font-semibold text-slate-100">
                                                        {share.path}
                                                    </span>
                                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono">
                                                        {share.allow_download ? 'Downloadable' : 'View-only'}
                                                    </span>
                                                </div>
                                                <div className="text-[11px] font-mono text-emerald-300 break-all">
                                                    {share.url}
                                                </div>
                                                <div className="text-[10px] text-slate-500">
                                                    Expires: {share.expires_at ? formatWorkspaceDate(share.expires_at) : 'Never'}
                                                </div>
                                            </div>
                                            <button
                                                type="button"
                                                onClick={() => handleRevokeShare(share.id)}
                                                disabled={revokingShareId === share.id}
                                                aria-label={`Revoke share ${share.path}`}
                                                className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-300 hover:bg-rose-500/25 disabled:opacity-40"
                                            >
                                                <Link2Off size={12} />
                                                <span>Revoke</span>
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </section>
    );
}
