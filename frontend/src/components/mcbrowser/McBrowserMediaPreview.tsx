'use client';

import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
    X,
    ChevronLeft,
    ChevronRight,
    ZoomIn,
    ZoomOut,
    RotateCcw,
    Maximize2,
    Minimize2,
    Download,
    ExternalLink,
    Edit3,
    Trash2,
    Info,
    FileSpreadsheet,
    BookOpen,
    AlertTriangle,
    Loader2,
    Subtitles,
    Image as ImageIcon,
    Minus,
    Plus,
} from 'lucide-react';
import { McBrowserEntry, extractMcBrowserError, formatBytes } from '@/lib/mcbrowser';
import { McBrowserPolicyPermissions } from '@/lib/mcbrowser-workspace';
import {
    AVAILABLE_CSV_ENCODINGS,
    EPUB_DEFAULT_FONT_SIZE,
    EPUB_FONT_STEP,
    EPUB_MAX_FONT_SIZE,
    EPUB_MIN_FONT_SIZE,
    MAX_CSV_PREVIEW_BYTES,
    McBrowserCsvSeparatorMode,
    McBrowserEpubBook,
    McBrowserImageResolution,
    McBrowserSubtitleTrack,
    McBrowserThumbnailSize,
    VIDEO_PLAYBACK_RATES,
    buildMcBrowserMediaUrl,
    buildMcBrowserSubtitleUrl,
    buildMcBrowserThumbnailUrl,
    classifyMcBrowserMediaCategory,
    decodeCsvBuffer,
    discoverClientSubtitleEntries,
    extractSubtitleLabel,
    fetchMcBrowserCsvBuffer,
    fetchMcBrowserEpub,
    fetchMcBrowserMediaMetadata,
    fetchMcBrowserSubtitles,
    isUnsafeInlineExtension,
    parseCsvContent,
    readPersistedEpubFontSize,
    readPersistedEpubProgress,
    writePersistedEpubFontSize,
    writePersistedEpubProgress,
} from '@/lib/mcbrowser-media';

export interface McBrowserImageThumbnailProps {
    entry: Pick<McBrowserEntry, 'name' | 'path' | 'kind' | 'target_kind'>;
    size?: McBrowserThumbnailSize;
    className?: string;
    alt?: string;
}

export function McBrowserImageThumbnail({
    entry,
    size = 'thumb',
    className = 'h-16 w-16 object-cover rounded',
    alt,
}: McBrowserImageThumbnailProps) {
    const [failed, setFailed] = useState(false);

    const src = useMemo(() => {
        const isFileTarget =
            entry.kind === 'file' || (entry.kind === 'symlink' && entry.target_kind === 'file');
        if (!isFileTarget || classifyMcBrowserMediaCategory(entry.name || entry.path) !== 'image') {
            return null;
        }
        try {
            return buildMcBrowserThumbnailUrl(entry.path, size);
        } catch {
            return null;
        }
    }, [entry.kind, entry.target_kind, entry.name, entry.path, size]);

    if (!src || failed) {
        return (
            <div
                data-testid="mcbrowser-thumbnail-fallback"
                className="flex items-center justify-center bg-slate-800/70 text-slate-400 rounded p-2"
            >
                <ImageIcon className="h-6 w-6" />
            </div>
        );
    }

    return (
        // eslint-disable-next-line @next/next/no-img-element
        <img
            src={src}
            alt={alt ?? entry.name}
            loading="lazy"
            onError={() => setFailed(true)}
            className={className}
            data-testid={`mcbrowser-thumbnail-${size}`}
        />
    );
}

export interface McBrowserMediaPreviewProps {
    entry: McBrowserEntry | null;
    entries?: McBrowserEntry[];
    permissions?: Partial<McBrowserPolicyPermissions>;
    resizePreview?: boolean;
    initialFullSize?: boolean;
    subtitles?: McBrowserSubtitleTrack[];
    csvContent?: ArrayBuffer | string;
    epubBook?: McBrowserEpubBook;
    onClose: () => void;
    onSelectEntry?: (entry: McBrowserEntry) => void;
    onEditAsText?: (entry: McBrowserEntry) => void;
    onRename?: (entry: McBrowserEntry) => void;
    onDelete?: (entry: McBrowserEntry) => void;
    onDownload?: (entry: McBrowserEntry) => void;
    onOpenDirect?: (entry: McBrowserEntry, directUrl: string) => void;
    onShowInfo?: (entry: McBrowserEntry) => void;
}

const DEFAULT_PERMS: McBrowserPolicyPermissions = {
    read: true,
    create: true,
    rename: true,
    modify: true,
    delete: true,
    share: true,
    download: true,
};

const EMPTY_ENTRIES: McBrowserEntry[] = [];

export default function McBrowserMediaPreview({
    entry,
    entries = EMPTY_ENTRIES,
    permissions,
    resizePreview = true,
    initialFullSize = false,
    subtitles: propSubtitles,
    csvContent: propCsvContent,
    epubBook: propEpubBook,
    onClose,
    onSelectEntry,
    onEditAsText,
    onRename,
    onDelete,
    onDownload,
    onOpenDirect,
    onShowInfo,
}: McBrowserMediaPreviewProps) {
    const effectivePerms: McBrowserPolicyPermissions = {
        ...DEFAULT_PERMS,
        ...permissions,
    };

    const entryPath = entry?.path ?? null;
    const entryName = entry?.name ?? null;
    const entrySize = entry?.size ?? 0;

    const [fullSizeImage, setFullSizeImage] = useState<boolean>(initialFullSize);
    const [zoomState, setZoomState] = useState<{ path: string | null; scale: number }>({
        path: entryPath,
        scale: 1,
    });
    const [panState, setPanState] = useState<{ path: string | null; x: number; y: number }>({
        path: entryPath,
        x: 0,
        y: 0,
    });
    const [isDraggingImage, setIsDraggingImage] = useState<boolean>(false);
    const dragStartRef = useRef<{ x: number; y: number } | null>(null);
    const [imageErrorState, setImageErrorState] = useState<{
        path: string | null;
        message: string | null;
    }>({ path: entryPath, message: null });
    const [imageResState, setImageResState] = useState<{
        path: string | null;
        resolution: McBrowserImageResolution | null;
    }>({ path: entryPath, resolution: null });

    const zoomScale = zoomState.path === entryPath ? zoomState.scale : 1;
    const panOffset =
        panState.path === entryPath ? { x: panState.x, y: panState.y } : { x: 0, y: 0 };
    const imageError = imageErrorState.path === entryPath ? imageErrorState.message : null;
    const imageResolution = imageResState.path === entryPath ? imageResState.resolution : null;

    const setZoomScale = useCallback(
        (updater: number | ((prev: number) => number)) => {
            setZoomState((prev) => {
                const base = prev.path === entryPath ? prev.scale : 1;
                const next = typeof updater === 'function' ? updater(base) : updater;
                return { path: entryPath, scale: next };
            });
        },
        [entryPath]
    );

    const setPanOffset = useCallback(
        (next: { x: number; y: number }) => {
            setPanState({ path: entryPath, x: next.x, y: next.y });
        },
        [entryPath]
    );

    const setImageError = useCallback(
        (message: string | null) => {
            setImageErrorState({ path: entryPath, message });
        },
        [entryPath]
    );

    const setImageResolution = useCallback(
        (resolution: McBrowserImageResolution | null) => {
            setImageResState({ path: entryPath, resolution });
        },
        [entryPath]
    );

    // Video & Audio state
    const videoRef = useRef<HTMLVideoElement | null>(null);
    const [autoPlayMedia, setAutoPlayMedia] = useState<boolean>(false);
    const [playbackRate, setPlaybackRate] = useState<number>(1);
    const [remoteSubtitlesState, setRemoteSubtitlesState] = useState<{
        path: string | null;
        tracks: McBrowserSubtitleTrack[];
    }>({ path: null, tracks: [] });

    // CSV state
    const [fetchedCsvState, setFetchedCsvState] = useState<{
        path: string | null;
        buffer: ArrayBuffer | string | null;
        error: string | null;
        done: boolean;
    }>({ path: null, buffer: null, error: null, done: false });
    const [csvSeparatorMode, setCsvSeparatorMode] = useState<McBrowserCsvSeparatorMode>('both');
    const [csvEncoding, setCsvEncoding] = useState<string>('utf-8');
    const [csvEncodingSearch, setCsvEncodingSearch] = useState<string>('');
    const [csvEncodingDropdownOpen, setCsvEncodingDropdownOpen] = useState<boolean>(false);

    // EPUB state
    const [fetchedEpubState, setFetchedEpubState] = useState<{
        path: string | null;
        book: McBrowserEpubBook | null;
        error: string | null;
        done: boolean;
    }>({ path: null, book: null, error: null, done: false });
    const [epubChapterState, setEpubChapterState] = useState<{
        path: string | null;
        index: number;
    }>({
        path: entryPath,
        index: readPersistedEpubProgress(entryPath ?? undefined),
    });
    const [epubFontSize, setEpubFontSize] = useState<number>(() => readPersistedEpubFontSize());

    const category = useMemo(() => {
        if (!entryPath && !entryName) return 'unsupported';
        return classifyMcBrowserMediaCategory(entryName || entryPath || '');
    }, [entryName, entryPath]);

    const unsafeBlocked = useMemo(() => {
        if (!entryPath && !entryName) return false;
        return isUnsafeInlineExtension(entryName || entryPath || '');
    }, [entryName, entryPath]);

    // Filter navigable files (including confined file symlinks) in the current directory listing
    const navigableEntries = useMemo(() => {
        return entries.filter(
            (item) =>
                item.kind === 'file' || (item.kind === 'symlink' && item.target_kind === 'file')
        );
    }, [entries]);

    const currentEntryIndex = useMemo(() => {
        if (!entryPath) return -1;
        return navigableEntries.findIndex((item) => item.path === entryPath);
    }, [entryPath, navigableEntries]);

    const previousEntry =
        currentEntryIndex > 0 ? navigableEntries[currentEntryIndex - 1] : null;
    const nextEntry =
        currentEntryIndex >= 0 && currentEntryIndex < navigableEntries.length - 1
            ? navigableEntries[currentEntryIndex + 1]
            : null;

    const handlePrev = useCallback(() => {
        if (previousEntry && onSelectEntry) {
            onSelectEntry(previousEntry);
        }
    }, [previousEntry, onSelectEntry]);

    const handleNext = useCallback(() => {
        if (nextEntry && onSelectEntry) {
            onSelectEntry(nextEntry);
        }
    }, [nextEntry, onSelectEntry]);

    // Keyboard navigation (ArrowLeft, ArrowRight, Escape)
    useEffect(() => {
        if (!entryPath) return;
        const onKeyDown = (event: KeyboardEvent) => {
            const target = event.target as HTMLElement | null;
            if (
                target &&
                (target.tagName === 'INPUT' ||
                    target.tagName === 'SELECT' ||
                    target.tagName === 'TEXTAREA')
            ) {
                return;
            }
            if (event.key === 'ArrowLeft') {
                if (previousEntry && onSelectEntry) {
                    event.preventDefault();
                    onSelectEntry(previousEntry);
                }
            } else if (event.key === 'ArrowRight') {
                if (nextEntry && onSelectEntry) {
                    event.preventDefault();
                    onSelectEntry(nextEntry);
                }
            } else if (event.key === 'Escape') {
                event.preventDefault();
                onClose();
            }
        };
        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, [entryPath, previousEntry, nextEntry, onSelectEntry, onClose]);

    // Load image metadata or video subtitle sidecars asynchronously
    useEffect(() => {
        if (!entryPath) return;
        const controller = new AbortController();

        if (category === 'image') {
            void fetchMcBrowserMediaMetadata(entryPath, controller.signal)
                .then((meta) => {
                    if (!controller.signal.aborted && meta.resolution) {
                        setImageResState({ path: entryPath, resolution: meta.resolution });
                    }
                })
                .catch(() => {
                    // Metadata is optional enhancement
                });
        } else if (category === 'video' && (!propSubtitles || propSubtitles.length === 0)) {
            void fetchMcBrowserSubtitles(entryPath, controller.signal)
                .then((remoteTracks) => {
                    if (!controller.signal.aborted && remoteTracks.length > 0) {
                        setRemoteSubtitlesState({ path: entryPath, tracks: remoteTracks });
                    }
                })
                .catch(() => {
                    // Keep client-discovered tracks if endpoint fails
                });
        }

        return () => controller.abort();
    }, [entryPath, category, propSubtitles]);

    const discoveredSubtitles = useMemo(() => {
        if (category !== 'video' || !entryPath) return [];
        if (propSubtitles && propSubtitles.length > 0) {
            return propSubtitles;
        }
        if (remoteSubtitlesState.path === entryPath && remoteSubtitlesState.tracks.length > 0) {
            return remoteSubtitlesState.tracks;
        }
        return discoverClientSubtitleEntries(entryPath, entries);
    }, [category, entryPath, propSubtitles, remoteSubtitlesState, entries]);

    // Load CSV content asynchronously when needed
    useEffect(() => {
        if (
            !entryPath ||
            category !== 'csv' ||
            entrySize > MAX_CSV_PREVIEW_BYTES ||
            propCsvContent !== undefined
        ) {
            return;
        }
        const controller = new AbortController();
        void fetchMcBrowserCsvBuffer(entryPath, controller.signal)
            .then((buffer) => {
                if (!controller.signal.aborted) {
                    setFetchedCsvState({
                        path: entryPath,
                        buffer,
                        error: null,
                        done: true,
                    });
                }
            })
            .catch((err) => {
                if (!controller.signal.aborted) {
                    setFetchedCsvState({
                        path: entryPath,
                        buffer: null,
                        error: extractMcBrowserError(err, 'Failed to load CSV preview.'),
                        done: true,
                    });
                }
            });

        return () => controller.abort();
    }, [entryPath, entrySize, category, propCsvContent]);

    const csvOversizedError =
        category === 'csv' && entrySize > MAX_CSV_PREVIEW_BYTES
            ? 'CSV file exceeds the 5 MiB preview limit. Download the file to view it.'
            : null;
    const csvBuffer =
        category !== 'csv' || csvOversizedError
            ? null
            : propCsvContent !== undefined
              ? propCsvContent
              : fetchedCsvState.path === entryPath
                ? fetchedCsvState.buffer
                : null;
    const csvError =
        csvOversizedError ??
        (propCsvContent === undefined && fetchedCsvState.path === entryPath
            ? fetchedCsvState.error
            : null);
    const csvLoading =
        category === 'csv' &&
        !csvOversizedError &&
        propCsvContent === undefined &&
        (fetchedCsvState.path !== entryPath || !fetchedCsvState.done);

    // Load EPUB book asynchronously when needed
    useEffect(() => {
        if (!entryPath || category !== 'epub' || propEpubBook) return;
        const controller = new AbortController();
        void fetchMcBrowserEpub(entryPath, controller.signal)
            .then((book) => {
                if (!controller.signal.aborted) {
                    setFetchedEpubState({
                        path: entryPath,
                        book,
                        error: null,
                        done: true,
                    });
                    const savedIdx = readPersistedEpubProgress(entryPath);
                    const validIdx =
                        book.chapters.length > 0
                            ? Math.min(savedIdx, book.chapters.length - 1)
                            : 0;
                    setEpubChapterState({ path: entryPath, index: validIdx });
                }
            })
            .catch((err) => {
                if (!controller.signal.aborted) {
                    setFetchedEpubState({
                        path: entryPath,
                        book: null,
                        error: extractMcBrowserError(err, 'Failed to load EPUB book.'),
                        done: true,
                    });
                }
            });

        return () => controller.abort();
    }, [entryPath, category, propEpubBook]);

    const epubData =
        category !== 'epub'
            ? null
            : propEpubBook ??
              (fetchedEpubState.path === entryPath ? fetchedEpubState.book : null);
    const epubError =
        category === 'epub' && !propEpubBook && fetchedEpubState.path === entryPath
            ? fetchedEpubState.error
            : null;
    const epubLoading =
        category === 'epub' &&
        !propEpubBook &&
        (fetchedEpubState.path !== entryPath || !fetchedEpubState.done);

    const rawEpubChapterIndex =
        epubChapterState.path === entryPath
            ? epubChapterState.index
            : readPersistedEpubProgress(entryPath ?? undefined);
    const epubChapterIndex =
        epubData && epubData.chapters.length > 0
            ? Math.max(0, Math.min(epubData.chapters.length - 1, rawEpubChapterIndex))
            : 0;

    // Sync video playbackRate
    useEffect(() => {
        if (videoRef.current) {
            videoRef.current.playbackRate = playbackRate;
        }
    }, [playbackRate, entryPath]);

    const parsedCsvResult = useMemo(() => {
        if (category !== 'csv' || csvBuffer === null) {
            return { data: { headers: [], rows: [] }, error: null as string | null };
        }
        try {
            const decodedText = decodeCsvBuffer(csvBuffer, csvEncoding);
            const data = parseCsvContent(decodedText, csvSeparatorMode);
            return { data, error: null };
        } catch (err) {
            return {
                data: { headers: [], rows: [] },
                error: extractMcBrowserError(err, 'Failed to parse CSV content.'),
            };
        }
    }, [category, csvBuffer, csvEncoding, csvSeparatorMode]);

    const filteredEncodings = useMemo(() => {
        const needle = csvEncodingSearch.trim().toLowerCase();
        if (!needle) return AVAILABLE_CSV_ENCODINGS;
        return AVAILABLE_CSV_ENCODINGS.filter((enc) => enc.toLowerCase().includes(needle));
    }, [csvEncodingSearch]);

    if (!entry) {
        return null;
    }

    const directMediaUrl = !unsafeBlocked ? buildMcBrowserMediaUrl(entry.path) : '';
    const imagePreviewUrl =
        category === 'image' && !unsafeBlocked
            ? resizePreview && !fullSizeImage
                ? buildMcBrowserThumbnailUrl(entry.path, 'big')
                : directMediaUrl
            : '';

    const handleCycleImageZoom = () => {
        setZoomScale((prev) => {
            if (prev === 1) return 2;
            if (prev === 2) return 4;
            setPanOffset({ x: 0, y: 0 });
            return 1;
        });
    };

    const handleChangeEpubFontSize = (nextSize: number) => {
        const persisted = writePersistedEpubFontSize(nextSize);
        setEpubFontSize(persisted);
    };

    const handleChangeEpubChapter = (nextIndex: number) => {
        if (!epubData || epubData.chapters.length === 0) return;
        const clamped = Math.max(0, Math.min(epubData.chapters.length - 1, nextIndex));
        setEpubChapterState({ path: entry.path, index: clamped });
        writePersistedEpubProgress(clamped, entry.path);
    };

    const currentEpubChapter =
        epubData && epubData.chapters.length > 0
            ? epubData.chapters[Math.min(epubChapterIndex, epubData.chapters.length - 1)]
            : null;

    return (
        <div
            data-testid="mcbrowser-media-preview"
            role="dialog"
            aria-label={`Preview ${entry.name}`}
            className="fixed inset-0 z-50 flex flex-col bg-slate-950/95 text-slate-100"
        >
            {/* Header Bar */}
            <header className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4 py-3">
                <div className="flex items-center gap-3 min-w-0">
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close preview"
                        data-testid="preview-close-button"
                        className="rounded-lg p-1.5 text-slate-300 hover:bg-slate-800 hover:text-white"
                    >
                        <X className="h-5 w-5" />
                    </button>
                    <div className="min-w-0">
                        <h2
                            className="truncate text-sm font-semibold text-slate-100"
                            data-testid="preview-title"
                        >
                            {entry.name}
                        </h2>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                            <span>{formatBytes(entry.size)}</span>
                            {imageResolution && (
                                <span data-testid="preview-image-resolution">
                                    {imageResolution.width} &times; {imageResolution.height}
                                </span>
                            )}
                        </div>
                    </div>
                </div>

                {/* Action Toolbar */}
                <div className="flex items-center gap-2">
                    {category === 'image' && resizePreview && (
                        <button
                            type="button"
                            onClick={() => setFullSizeImage((prev) => !prev)}
                            data-testid="preview-toggle-size-button"
                            title={fullSizeImage ? 'Show resized preview (1080p)' : 'Show original full size (HD)'}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                        >
                            {fullSizeImage ? (
                                <>
                                    <Minimize2 className="h-3.5 w-3.5" />
                                    <span>Fit 1080p</span>
                                </>
                            ) : (
                                <>
                                    <Maximize2 className="h-3.5 w-3.5" />
                                    <span>HD Full Size</span>
                                </>
                            )}
                        </button>
                    )}

                    {category === 'csv' && effectivePerms.modify && onEditAsText && (
                        <button
                            type="button"
                            onClick={() => onEditAsText(entry)}
                            data-testid="preview-edit-as-text-button"
                            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                        >
                            <Edit3 className="h-3.5 w-3.5" />
                            <span>Edit as Text</span>
                        </button>
                    )}

                    {effectivePerms.rename && onRename && (
                        <button
                            type="button"
                            onClick={() => onRename(entry)}
                            data-testid="preview-rename-button"
                            className="rounded-lg p-1.5 text-slate-300 hover:bg-slate-800 hover:text-white"
                            title="Rename"
                        >
                            <Edit3 className="h-4 w-4" />
                        </button>
                    )}

                    {effectivePerms.delete && onDelete && (
                        <button
                            type="button"
                            onClick={() => onDelete(entry)}
                            data-testid="preview-delete-button"
                            className="rounded-lg p-1.5 text-rose-400 hover:bg-rose-950/50 hover:text-rose-300"
                            title="Delete"
                        >
                            <Trash2 className="h-4 w-4" />
                        </button>
                    )}

                    {effectivePerms.download && onDownload && (
                        <button
                            type="button"
                            onClick={() => onDownload(entry)}
                            data-testid="preview-download-button"
                            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                            title="Download"
                        >
                            <Download className="h-3.5 w-3.5" />
                            <span>Download</span>
                        </button>
                    )}

                    {effectivePerms.download &&
                        directMediaUrl &&
                        (category === 'image' ||
                            category === 'video' ||
                            category === 'audio' ||
                            category === 'pdf') && (
                            <button
                                type="button"
                                onClick={() => {
                                    if (onOpenDirect) {
                                        onOpenDirect(entry, directMediaUrl);
                                    } else if (typeof window !== 'undefined') {
                                        window.open(directMediaUrl, '_blank', 'noopener,noreferrer');
                                    }
                                }}
                                data-testid="preview-open-direct-button"
                                className="rounded-lg p-1.5 text-slate-300 hover:bg-slate-800 hover:text-white"
                                title="Open direct stream"
                            >
                                <ExternalLink className="h-4 w-4" />
                            </button>
                        )}

                    {onShowInfo && (
                        <button
                            type="button"
                            onClick={() => onShowInfo(entry)}
                            data-testid="preview-info-button"
                            className="rounded-lg p-1.5 text-slate-300 hover:bg-slate-800 hover:text-white"
                            title="File info"
                        >
                            <Info className="h-4 w-4" />
                        </button>
                    )}
                </div>
            </header>

            {/* Main Viewer Stage */}
            <div className="relative flex flex-1 items-center justify-center overflow-hidden p-4">
                {/* Unsafe SVG / HTML Blocking Notice */}
                {unsafeBlocked && (
                    <div
                        data-testid="preview-unsafe-blocked"
                        className="flex max-w-md flex-col items-center gap-3 rounded-xl border border-amber-500/40 bg-slate-900 p-6 text-center"
                    >
                        <AlertTriangle className="h-10 w-10 text-amber-400" />
                        <h3 className="text-base font-semibold text-slate-100">
                            Active Markup Preview Blocked
                        </h3>
                        <p className="text-xs text-slate-300">
                            Raw HTML and SVG files are not rendered as inline media to prevent
                            unsandboxed script execution. Use the text editor or download the file.
                        </p>
                    </div>
                )}

                {/* Image Viewer with Pan & Zoom (ExtendedImage parity) */}
                {!unsafeBlocked && category === 'image' && (
                    <div className="relative flex h-full w-full flex-col items-center justify-center overflow-hidden">
                        {imageError ? (
                            <div
                                data-testid="preview-image-error"
                                className="flex max-w-md flex-col items-center gap-2 rounded-xl border border-rose-500/40 bg-slate-900 p-6 text-center"
                            >
                                <AlertTriangle className="h-8 w-8 text-rose-400" />
                                <p className="text-sm text-rose-200">{imageError}</p>
                            </div>
                        ) : (
                            <div
                                className="flex h-full w-full items-center justify-center overflow-hidden cursor-grab active:cursor-grabbing"
                                onWheel={(e) => {
                                    e.preventDefault();
                                    const delta = e.deltaY < 0 ? 0.25 : -0.25;
                                    setZoomScale((prev) =>
                                        Math.min(4, Math.max(0.5, Number((prev + delta).toFixed(2))))
                                    );
                                }}
                                onMouseDown={(e) => {
                                    if (zoomScale <= 1) return;
                                    setIsDraggingImage(true);
                                    dragStartRef.current = {
                                        x: e.clientX - panOffset.x,
                                        y: e.clientY - panOffset.y,
                                    };
                                }}
                                onMouseMove={(e) => {
                                    if (!isDraggingImage || !dragStartRef.current) return;
                                    setPanOffset({
                                        x: e.clientX - dragStartRef.current.x,
                                        y: e.clientY - dragStartRef.current.y,
                                    });
                                }}
                                onMouseUp={() => setIsDraggingImage(false)}
                                onMouseLeave={() => setIsDraggingImage(false)}
                            >
                                {/* eslint-disable-next-line @next/next/no-img-element */}
                                <img
                                    src={imagePreviewUrl}
                                    alt={entry.name}
                                    data-testid="preview-image-element"
                                    onDoubleClick={handleCycleImageZoom}
                                    onLoad={(e) => {
                                        const img = e.currentTarget;
                                        if (!imageResolution && img.naturalWidth > 0 && img.naturalHeight > 0) {
                                            setImageResolution({
                                                width: img.naturalWidth,
                                                height: img.naturalHeight,
                                            });
                                        }
                                    }}
                                    onError={() =>
                                        setImageError(
                                            'Failed to render image preview (unsupported format or dimensions exceed 10000x10000 limit).'
                                        )
                                    }
                                    style={{
                                        transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoomScale})`,
                                        transition: isDraggingImage ? 'none' : 'transform 0.1s ease',
                                    }}
                                    className="max-h-full max-w-full object-contain select-none"
                                />
                            </div>
                        )}

                        {/* Image Zoom Controls */}
                        <div className="absolute bottom-4 flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/90 px-3 py-1.5 text-xs">
                            <button
                                type="button"
                                onClick={() =>
                                    setZoomScale((prev) => Math.max(0.5, Number((prev - 0.5).toFixed(2))))
                                }
                                data-testid="image-zoom-out"
                                aria-label="Zoom out"
                                className="p-1 text-slate-300 hover:text-white"
                            >
                                <ZoomOut className="h-4 w-4" />
                            </button>
                            <span data-testid="image-zoom-scale">{Math.round(zoomScale * 100)}%</span>
                            <button
                                type="button"
                                onClick={() =>
                                    setZoomScale((prev) => Math.min(4, Number((prev + 0.5).toFixed(2))))
                                }
                                data-testid="image-zoom-in"
                                aria-label="Zoom in"
                                className="p-1 text-slate-300 hover:text-white"
                            >
                                <ZoomIn className="h-4 w-4" />
                            </button>
                            <button
                                type="button"
                                onClick={() => {
                                    setZoomScale(1);
                                    setPanOffset({ x: 0, y: 0 });
                                }}
                                data-testid="image-zoom-reset"
                                aria-label="Reset zoom"
                                className="p-1 text-slate-300 hover:text-white"
                            >
                                <RotateCcw className="h-3.5 w-3.5" />
                            </button>
                        </div>
                    </div>
                )}

                {/* Video Viewer with Subtitle Sidecars & Playback Speeds */}
                {!unsafeBlocked && category === 'video' && (
                    <div className="flex h-full w-full max-w-5xl flex-col items-center justify-center gap-3">
                        <video
                            ref={videoRef}
                            src={directMediaUrl}
                            controls
                            autoPlay={autoPlayMedia}
                            preload="metadata"
                            onPlay={() => setAutoPlayMedia(true)}
                            data-testid="preview-video-element"
                            className="max-h-[78vh] w-full rounded-lg bg-black"
                        >
                            {discoveredSubtitles.map((track, idx) => (
                                <track
                                    key={track.path}
                                    kind="subtitles"
                                    src={track.url || buildMcBrowserSubtitleUrl(track.path)}
                                    label={track.label || extractSubtitleLabel(track.name || track.path)}
                                    srcLang={track.language ?? undefined}
                                    default={idx === 0}
                                />
                            ))}
                        </video>

                        <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-slate-800 bg-slate-900/90 px-4 py-2 text-xs text-slate-300 w-full">
                            <div className="flex items-center gap-2">
                                <button
                                    type="button"
                                    onClick={() => {
                                        if (videoRef.current) {
                                            videoRef.current.currentTime = Math.max(
                                                0,
                                                videoRef.current.currentTime - 5
                                            );
                                        }
                                    }}
                                    data-testid="video-skip-backward"
                                    className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
                                >
                                    -5s
                                </button>
                                <button
                                    type="button"
                                    onClick={() => {
                                        if (videoRef.current) {
                                            videoRef.current.currentTime += 5;
                                        }
                                    }}
                                    data-testid="video-skip-forward"
                                    className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
                                >
                                    +5s
                                </button>
                                <label htmlFor="video-playback-rate" className="ml-2 text-slate-400">
                                    Speed:
                                </label>
                                <select
                                    id="video-playback-rate"
                                    data-testid="video-playback-rate"
                                    value={playbackRate}
                                    onChange={(e) => setPlaybackRate(Number(e.target.value))}
                                    className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-slate-200"
                                >
                                    {VIDEO_PLAYBACK_RATES.map((rate) => (
                                        <option key={rate} value={rate}>
                                            {rate}x
                                        </option>
                                    ))}
                                </select>
                            </div>

                            <div
                                className="flex items-center gap-1.5 text-slate-400"
                                data-testid="video-subtitle-summary"
                            >
                                <Subtitles className="h-4 w-4 text-sky-400" />
                                <span>
                                    {discoveredSubtitles.length > 0
                                        ? `Subtitles (${discoveredSubtitles.length}): ${discoveredSubtitles
                                              .map((s) => s.label)
                                              .join(', ')}`
                                        : 'No subtitle sidecars detected'}
                                </span>
                            </div>
                        </div>
                    </div>
                )}

                {/* Audio Viewer */}
                {!unsafeBlocked && category === 'audio' && (
                    <div className="flex flex-col items-center gap-4 rounded-xl border border-slate-800 bg-slate-900 p-8 shadow-xl">
                        <p className="text-sm font-medium text-slate-200">{entry.name}</p>
                        <audio
                            src={directMediaUrl}
                            controls
                            autoPlay={autoPlayMedia}
                            onPlay={() => setAutoPlayMedia(true)}
                            data-testid="preview-audio-element"
                            className="w-80 sm:w-96"
                        />
                    </div>
                )}

                {/* PDF Viewer */}
                {!unsafeBlocked && category === 'pdf' && (
                    <object
                        data={directMediaUrl}
                        type="application/pdf"
                        data-testid="preview-pdf-object"
                        className="h-full w-full rounded-lg border border-slate-800 bg-slate-900"
                    >
                        <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
                            <p className="text-sm text-slate-300">
                                Inline PDF viewing is unavailable in this browser.
                            </p>
                            {effectivePerms.download && onDownload && (
                                <button
                                    type="button"
                                    onClick={() => onDownload(entry)}
                                    className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-medium text-white hover:bg-sky-500"
                                >
                                    Download PDF
                                </button>
                            )}
                        </div>
                    </object>
                )}

                {/* CSV Viewer (CsvViewer.vue parity: 5 MiB cap, delimiter & encoding selectors) */}
                {!unsafeBlocked && category === 'csv' && (
                    <div
                        data-testid="preview-csv-viewer"
                        className="flex h-full w-full max-w-6xl flex-col rounded-xl border border-slate-800 bg-slate-900 p-4"
                    >
                        <div className="mb-3 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
                            <div className="flex items-center gap-2">
                                <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
                                <label
                                    htmlFor="csv-column-separator"
                                    className="text-xs font-medium text-slate-300"
                                >
                                    Column Separator
                                </label>
                                <select
                                    id="csv-column-separator"
                                    data-testid="csv-separator-select"
                                    value={csvSeparatorMode}
                                    onChange={(e) =>
                                        setCsvSeparatorMode(e.target.value as McBrowserCsvSeparatorMode)
                                    }
                                    className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-100"
                                >
                                    <option value="comma">Comma (,)</option>
                                    <option value="semicolon">Semicolon (;)</option>
                                    <option value="both">Comma &amp; Semicolon (, / ;)</option>
                                </select>
                            </div>

                            {typeof csvBuffer !== 'string' && (
                                <div className="relative flex items-center gap-2">
                                    <label className="text-xs font-medium text-slate-300">
                                        Encoding
                                    </label>
                                    <button
                                        type="button"
                                        data-testid="csv-encoding-trigger"
                                        onClick={() =>
                                            setCsvEncodingDropdownOpen((prev) => !prev)
                                        }
                                        className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-100 hover:bg-slate-700"
                                    >
                                        {csvEncoding}
                                    </button>
                                    {csvEncodingDropdownOpen && (
                                        <div
                                            data-testid="csv-encoding-dropdown"
                                            className="absolute right-0 top-8 z-20 w-56 rounded-lg border border-slate-700 bg-slate-900 p-2 shadow-xl"
                                        >
                                            <input
                                                type="text"
                                                value={csvEncodingSearch}
                                                onChange={(e) =>
                                                    setCsvEncodingSearch(e.target.value)
                                                }
                                                placeholder="Search encoding..."
                                                data-testid="csv-encoding-search"
                                                className="mb-2 w-full rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-100"
                                            />
                                            <div className="max-h-48 overflow-y-auto">
                                                {filteredEncodings.map((enc) => (
                                                    <button
                                                        key={enc}
                                                        type="button"
                                                        data-testid={`csv-encoding-option-${enc}`}
                                                        onClick={() => {
                                                            setCsvEncoding(enc);
                                                            setCsvEncodingDropdownOpen(false);
                                                            setCsvEncodingSearch('');
                                                        }}
                                                        className={`block w-full rounded px-2 py-1 text-left text-xs ${
                                                            csvEncoding === enc
                                                                ? 'bg-sky-600/30 text-sky-200'
                                                                : 'text-slate-300 hover:bg-slate-800'
                                                        }`}
                                                    >
                                                        {enc}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>

                        {csvLoading ? (
                            <div className="flex flex-1 items-center justify-center gap-2 text-slate-400">
                                <Loader2 className="h-5 w-5 animate-spin" />
                                <span className="text-sm">Loading CSV data...</span>
                            </div>
                        ) : csvError || parsedCsvResult.error ? (
                            <div
                                data-testid="csv-error-banner"
                                className="flex flex-1 flex-col items-center justify-center gap-2 text-rose-300"
                            >
                                <AlertTriangle className="h-8 w-8 text-rose-400" />
                                <p className="text-sm">{csvError || parsedCsvResult.error}</p>
                            </div>
                        ) : parsedCsvResult.data.headers.length === 0 ? (
                            <div
                                data-testid="csv-empty-state"
                                className="flex flex-1 items-center justify-center text-sm text-slate-400"
                            >
                                CSV file is empty.
                            </div>
                        ) : (
                            <div className="flex flex-1 flex-col overflow-hidden">
                                <div className="flex-1 overflow-auto rounded border border-slate-800">
                                    <table
                                        data-testid="csv-table"
                                        className="w-full border-collapse text-left text-xs"
                                    >
                                        <thead className="sticky top-0 bg-slate-800 text-slate-200">
                                            <tr>
                                                {parsedCsvResult.data.headers.map((header, idx) => (
                                                    <th
                                                        key={idx}
                                                        className="border-b border-slate-700 px-3 py-2 font-semibold whitespace-nowrap"
                                                    >
                                                        {header}
                                                    </th>
                                                ))}
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {parsedCsvResult.data.rows.map((row, rIdx) => (
                                                <tr
                                                    key={rIdx}
                                                    className="border-b border-slate-800/80 odd:bg-slate-900 even:bg-slate-900/50 hover:bg-slate-800/60"
                                                >
                                                    {row.map((cell, cIdx) => (
                                                        <td
                                                            key={cIdx}
                                                            className="max-w-xs truncate px-3 py-1.5 text-slate-300"
                                                        >
                                                            {cell}
                                                        </td>
                                                    ))}
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                                {parsedCsvResult.data.rows.length > 100 && (
                                    <div
                                        data-testid="csv-row-count-info"
                                        className="mt-2 rounded bg-slate-800/80 px-3 py-1.5 text-xs text-sky-300"
                                    >
                                        Showing {parsedCsvResult.data.rows.length} rows
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {/* Safe Sandboxed EPUB Reader (Preview.vue parity: book-progress & book-size 100-150%) */}
                {!unsafeBlocked && category === 'epub' && (
                    <div
                        data-testid="preview-epub-reader"
                        className="flex h-full w-full max-w-4xl flex-col rounded-xl border border-slate-800 bg-slate-900 p-5"
                    >
                        {epubLoading ? (
                            <div className="flex flex-1 items-center justify-center gap-2 text-slate-400">
                                <Loader2 className="h-5 w-5 animate-spin" />
                                <span className="text-sm">Loading EPUB book...</span>
                            </div>
                        ) : epubError ? (
                            <div
                                data-testid="epub-error-banner"
                                className="flex flex-1 flex-col items-center justify-center gap-2 text-rose-300"
                            >
                                <AlertTriangle className="h-8 w-8 text-rose-400" />
                                <p className="text-sm">{epubError}</p>
                            </div>
                        ) : epubData && currentEpubChapter ? (
                            <>
                                <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                                    <div className="flex items-center gap-2 min-w-0">
                                        <BookOpen className="h-4 w-4 shrink-0 text-amber-400" />
                                        <div className="min-w-0">
                                            <h3
                                                data-testid="epub-book-title"
                                                className="truncate text-sm font-semibold text-slate-100"
                                            >
                                                {epubData.title}
                                            </h3>
                                            {epubData.author && (
                                                <p className="truncate text-xs text-slate-400">
                                                    {epubData.author}
                                                </p>
                                            )}
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-3">
                                        <select
                                            aria-label="Select chapter"
                                            data-testid="epub-chapter-select"
                                            value={epubChapterIndex}
                                            onChange={(e) =>
                                                handleChangeEpubChapter(Number(e.target.value))
                                            }
                                            className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-100"
                                        >
                                            {epubData.chapters.map((ch, idx) => (
                                                <option key={ch.id || idx} value={idx}>
                                                    {idx + 1}. {ch.title}
                                                </option>
                                            ))}
                                        </select>

                                        <div className="flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs">
                                            <button
                                                type="button"
                                                data-testid="epub-font-decrease"
                                                onClick={() =>
                                                    handleChangeEpubFontSize(
                                                        Math.max(
                                                            EPUB_MIN_FONT_SIZE,
                                                            epubFontSize - EPUB_FONT_STEP
                                                        )
                                                    )
                                                }
                                                aria-label="Decrease font size"
                                                className="p-1 text-slate-300 hover:text-white"
                                            >
                                                <Minus className="h-3 w-3" />
                                            </button>
                                            <span data-testid="epub-font-size">
                                                {epubFontSize || EPUB_DEFAULT_FONT_SIZE}%
                                            </span>
                                            <button
                                                type="button"
                                                data-testid="epub-font-increase"
                                                onClick={() =>
                                                    handleChangeEpubFontSize(
                                                        Math.min(
                                                            EPUB_MAX_FONT_SIZE,
                                                            epubFontSize + EPUB_FONT_STEP
                                                        )
                                                    )
                                                }
                                                aria-label="Increase font size"
                                                className="p-1 text-slate-300 hover:text-white"
                                            >
                                                <Plus className="h-3 w-3" />
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <article
                                    data-testid="epub-chapter-content"
                                    style={{ fontSize: `${epubFontSize}%` }}
                                    className="flex-1 overflow-y-auto space-y-4 px-2 leading-relaxed text-slate-200"
                                >
                                    <h4 className="text-lg font-semibold text-white">
                                        {currentEpubChapter.title}
                                    </h4>
                                    {currentEpubChapter.paragraphs.map((para, pIdx) => (
                                        <p key={pIdx} className="text-slate-200">
                                            {para}
                                        </p>
                                    ))}
                                </article>

                                <div className="mt-4 flex items-center justify-between border-t border-slate-800 pt-3 text-xs text-slate-400">
                                    <button
                                        type="button"
                                        disabled={epubChapterIndex <= 0}
                                        onClick={() =>
                                            handleChangeEpubChapter(epubChapterIndex - 1)
                                        }
                                        data-testid="epub-prev-chapter"
                                        className="rounded border border-slate-700 bg-slate-800 px-3 py-1 text-slate-200 disabled:opacity-40"
                                    >
                                        Previous Chapter
                                    </button>
                                    <span>
                                        Chapter {epubChapterIndex + 1} of {epubData.chapters.length}
                                    </span>
                                    <button
                                        type="button"
                                        disabled={epubChapterIndex >= epubData.chapters.length - 1}
                                        onClick={() =>
                                            handleChangeEpubChapter(epubChapterIndex + 1)
                                        }
                                        data-testid="epub-next-chapter"
                                        className="rounded border border-slate-700 bg-slate-800 px-3 py-1 text-slate-200 disabled:opacity-40"
                                    >
                                        Next Chapter
                                    </button>
                                </div>
                            </>
                        ) : null}
                    </div>
                )}

                {/* Unsupported / Binary Fallback */}
                {!unsafeBlocked && category === 'unsupported' && (
                    <div
                        data-testid="preview-unsupported-fallback"
                        className="flex max-w-md flex-col items-center gap-4 rounded-xl border border-slate-800 bg-slate-900 p-6 text-center"
                    >
                        <p className="text-sm text-slate-300">
                            No inline media preview is available for <strong>{entry.name}</strong>.
                        </p>
                        {effectivePerms.download && onDownload && (
                            <button
                                type="button"
                                onClick={() => onDownload(entry)}
                                className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-medium text-white hover:bg-sky-500"
                            >
                                <Download className="h-4 w-4" />
                                <span>Download File</span>
                            </button>
                        )}
                    </div>
                )}

                {/* Previous / Next Directory Item Navigation Buttons */}
                {previousEntry && onSelectEntry && (
                    <button
                        type="button"
                        onClick={handlePrev}
                        aria-label="Previous file"
                        title={`Previous: ${previousEntry.name}`}
                        data-testid="preview-prev-button"
                        className="absolute left-4 top-1/2 -translate-y-1/2 rounded-full border border-slate-700 bg-slate-900/90 p-2.5 text-slate-200 shadow-lg hover:bg-slate-800"
                    >
                        <ChevronLeft className="h-5 w-5" />
                    </button>
                )}

                {nextEntry && onSelectEntry && (
                    <button
                        type="button"
                        onClick={handleNext}
                        aria-label="Next file"
                        title={`Next: ${nextEntry.name}`}
                        data-testid="preview-next-button"
                        className="absolute right-4 top-1/2 -translate-y-1/2 rounded-full border border-slate-700 bg-slate-900/90 p-2.5 text-slate-200 shadow-lg hover:bg-slate-800"
                    >
                        <ChevronRight className="h-5 w-5" />
                    </button>
                )}
            </div>
        </div>
    );
}
