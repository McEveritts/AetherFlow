import {
    McBrowserRequestError,
    extractMcBrowserError,
    formatBytes,
    joinRelativePath,
    normalizeRelativePath,
    validateEntryName,
} from '@/lib/mcbrowser';
import {
    McBrowserResumableProgress,
    McBrowserUploadConflictPolicy,
    cancelMcBrowserResumable,
    isMcBrowserUploadUncertainError,
    uploadMcBrowserResumable,
} from '@/lib/mcbrowser-resumable';

export type UploadQueueStatus =
    | 'pending'
    | 'uploading'
    | 'paused'
    | 'pausing'
    | 'cancelling'
    | 'success'
    | 'error'
    | 'cancelled'
    | 'uncertain';

export interface UploadQueueItem {
    id: string;
    name: string;
    targetPath: string;
    size: number;
    status: UploadQueueStatus;
    error?: string;
    uploadedBytes?: number;
    speedBytesPerSecond?: number;
    kind?: 'file' | 'directory';
    conflictDetected?: boolean;
    skipped?: boolean;
}

export function summarizeMcBrowserUploadQueue(items: readonly UploadQueueItem[]) {
    let confirmedBytes = 0;
    let totalBytes = 0;
    let remainingBytes = 0;
    let speedBytesPerSecond = 0;
    let hasPausedWork = false;
    for (const item of items) {
        if (item.kind === 'directory' || item.skipped) continue;
        const size = Number.isFinite(item.size) ? Math.max(0, item.size) : 0;
        const confirmed = item.status === 'success' ? size
            : typeof item.uploadedBytes === 'number' && Number.isFinite(item.uploadedBytes)
                ? Math.min(size, Math.max(0, item.uploadedBytes)) : 0;
        totalBytes += size;
        confirmedBytes += confirmed;
        if (item.status === 'pending' || item.status === 'uploading') {
            remainingBytes += size - confirmed;
        }
        if (item.status === 'paused' || item.status === 'pausing') hasPausedWork = true;
        if (item.status === 'uploading' && typeof item.speedBytesPerSecond === 'number'
            && Number.isFinite(item.speedBytesPerSecond) && item.speedBytesPerSecond > 0) {
            speedBytesPerSecond += item.speedBytesPerSecond;
        }
    }
    return {
        confirmedBytes, totalBytes, speedBytesPerSecond,
        etaSeconds: speedBytesPerSecond > 0 && !hasPausedWork
            ? Math.ceil(remainingBytes / speedBytesPerSecond) : undefined,
    };
}

export function formatMcBrowserUploadEta(seconds: number | undefined): string | undefined {
    if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return undefined;
    const duration = Math.ceil(seconds);
    const hours = Math.floor(duration / 3600);
    const minutes = Math.floor((duration % 3600) / 60);
    const remainder = duration % 60;
    return [hours, minutes, remainder].map((part) => String(part).padStart(2, '0')).join(':');
}

export type UploadQueueTransportFn = (
    path: string,
    file: File,
    signal: AbortSignal,
    onProgress?: (progress: McBrowserResumableProgress) => void,
    conflict?: McBrowserUploadConflictPolicy
) => Promise<unknown>;

export type UploadQueueCancelSessionFn = (
    path: string,
    file: File,
    signal?: AbortSignal,
    conflict?: McBrowserUploadConflictPolicy
) => Promise<{ cancelled?: boolean; sessionId?: string } | unknown>;

export interface McBrowserUploadQueueOptions {
    upload?: UploadQueueTransportFn;
    cancelSession?: UploadQueueCancelSessionFn;
    ensureDirectory?: (path: string, signal: AbortSignal) => Promise<unknown>;
    onChange: (items: UploadQueueItem[]) => void;
    onIdle?: () => void;
    concurrency?: number;
    maxFiles?: number;
    maxTotalBytes?: number;
}

interface InternalQueueEntry {
    id: string;
    name: string;
    targetPath: string;
    directoryChain: string[];
    size: number;
    uploadedBytes: number;
    speedBytesPerSecond: number;
    kind: 'file' | 'directory';
    status: UploadQueueStatus;
    error?: string;
    file: File | null;
    canRetryDirectory: boolean;
    maxFileBytes: number;
    controller: AbortController | null;
    uploadStarted: boolean;
    cancelRequested: boolean;
    pauseRequested: boolean;
    resumeRequested?: boolean;
    conflict?: McBrowserUploadConflictPolicy;
    conflictDetected?: boolean;
    skipped?: boolean;
}

function waitForDirectoryPreparation(promise: Promise<unknown>, signal: AbortSignal): Promise<unknown> {
    return new Promise((resolve, reject) => {
        const handleAbort = () => {
            signal.removeEventListener('abort', handleAbort);
            reject(new DOMException('Directory preparation interrupted.', 'AbortError'));
        };
        signal.addEventListener('abort', handleAbort, { once: true });
        promise.then(
            (value) => {
                signal.removeEventListener('abort', handleAbort);
                resolve(value);
            },
            (error) => {
                signal.removeEventListener('abort', handleAbort);
                reject(error);
            }
        );
        if (signal.aborted) handleAbort();
    });
}

export interface DroppedUploadItems {
    files: File[];
    emptyDirectories: string[];
}

interface WebkitFileSystemEntry {
    isFile: boolean;
    isDirectory: boolean;
    name: string;
    fullPath?: string;
}

interface WebkitFileSystemFileEntry extends WebkitFileSystemEntry {
    isFile: true;
    isDirectory: false;
    file: (
        successCallback: (file: File) => void,
        errorCallback?: (error: unknown) => void
    ) => void;
}

interface WebkitFileSystemDirectoryReader {
    readEntries: (
        successCallback: (entries: WebkitFileSystemEntry[]) => void,
        errorCallback?: (error: unknown) => void
    ) => void;
}

interface WebkitFileSystemDirectoryEntry extends WebkitFileSystemEntry {
    isFile: false;
    isDirectory: true;
    createReader: () => WebkitFileSystemDirectoryReader;
}

export const DEFAULT_UPLOAD_CONCURRENCY = 5;
export const MIN_UPLOAD_CONCURRENCY = 1;
export const MAX_UPLOAD_CONCURRENCY = 5;
export const DEFAULT_MAX_UPLOAD_FILES = 1000;
export const DEFAULT_MAX_TOTAL_UPLOAD_BYTES = 16 * 1024 * 1024 * 1024;

function clampConcurrency(value: number | undefined): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return DEFAULT_UPLOAD_CONCURRENCY;
    }
    const integerValue = Math.trunc(value);
    if (integerValue < MIN_UPLOAD_CONCURRENCY) {
        return MIN_UPLOAD_CONCURRENCY;
    }
    if (integerValue > MAX_UPLOAD_CONCURRENCY) {
        return MAX_UPLOAD_CONCURRENCY;
    }
    return integerValue;
}

function normalizePositiveLimit(value: number | undefined, fallback: number): number {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 1) {
        return fallback;
    }
    return Math.trunc(value);
}

function getWebkitRelativePath(file: File): string {
    const candidate = (file as File & { webkitRelativePath?: unknown }).webkitRelativePath;
    return typeof candidate === 'string' ? candidate : '';
}

function attachRelativePathToFile(file: File, relativePath: string): File {
    if (!relativePath) {
        return file;
    }
    try {
        Object.defineProperty(file, 'webkitRelativePath', {
            value: relativePath,
            configurable: true,
            enumerable: true,
        });
        return file;
    } catch {
        const cloned = new File([file], file.name, {
            type: file.type,
            lastModified: file.lastModified,
        });
        Object.defineProperty(cloned, 'webkitRelativePath', {
            value: relativePath,
            configurable: true,
            enumerable: true,
        });
        return cloned;
    }
}

function readFileEntry(entry: WebkitFileSystemFileEntry): Promise<File> {
    return new Promise<File>((resolve, reject) => {
        entry.file(
            (file) => resolve(file),
            (error) => reject(error ?? new Error(`Unable to read dropped file "${entry.name}".`))
        );
    });
}

async function readAllDirectoryEntries(
    reader: WebkitFileSystemDirectoryReader
): Promise<WebkitFileSystemEntry[]> {
    const collected: WebkitFileSystemEntry[] = [];
    while (true) {
        const batch = await new Promise<WebkitFileSystemEntry[]>((resolve, reject) => {
            reader.readEntries(
                (entries) => resolve(Array.isArray(entries) ? entries : []),
                (error) => reject(error ?? new Error('Unable to read directory entries.'))
            );
        });
        if (batch.length === 0) {
            break;
        }
        collected.push(...batch);
    }
    return collected;
}

async function traverseWebkitEntry(
    entry: WebkitFileSystemEntry,
    parentRelativePath: string,
    result: DroppedUploadItems
): Promise<void> {
    const entryName = typeof entry.name === 'string' ? entry.name : '';
    const currentRelativePath = parentRelativePath
        ? `${parentRelativePath}/${entryName}`
        : entryName;

    if (entry.isFile) {
        const rawFile = await readFileEntry(entry as WebkitFileSystemFileEntry);
        if (parentRelativePath) {
            result.files.push(attachRelativePathToFile(rawFile, currentRelativePath));
        } else {
            result.files.push(rawFile);
        }
        return;
    }

    if (entry.isDirectory) {
        const dirEntry = entry as WebkitFileSystemDirectoryEntry;
        const children = await readAllDirectoryEntries(dirEntry.createReader());
        if (children.length === 0) {
            result.emptyDirectories.push(currentRelativePath);
            return;
        }
        for (const child of children) {
            await traverseWebkitEntry(child, currentRelativePath, result);
        }
    }
}

export async function scanTransferItems(
    dataTransfer: DataTransfer | null | undefined
): Promise<DroppedUploadItems> {
    if (!dataTransfer) {
        return { files: [], emptyDirectories: [] };
    }

    const rawItems = dataTransfer.items ? Array.from(dataTransfer.items) : [];
    const rootEntries: WebkitFileSystemEntry[] = [];

    for (const item of rawItems) {
        if (!item || (item.kind && item.kind !== 'file')) {
            continue;
        }
        const itemWithEntry = item as DataTransferItem & {
            webkitGetAsEntry?: () => WebkitFileSystemEntry | null;
            getAsEntry?: () => WebkitFileSystemEntry | null;
        };
        const getEntryFn =
            typeof itemWithEntry.webkitGetAsEntry === 'function'
                ? itemWithEntry.webkitGetAsEntry
                : typeof itemWithEntry.getAsEntry === 'function'
                ? itemWithEntry.getAsEntry
                : null;
        if (getEntryFn) {
            const entry = getEntryFn.call(itemWithEntry);
            if (entry) {
                rootEntries.push(entry);
            }
        }
    }

    if (rootEntries.length === 0) {
        const fallbackFiles = dataTransfer.files ? Array.from(dataTransfer.files) : [];
        return {
            files: fallbackFiles,
            emptyDirectories: [],
        };
    }

    const result: DroppedUploadItems = {
        files: [],
        emptyDirectories: [],
    };

    for (const rootEntry of rootEntries) {
        await traverseWebkitEntry(rootEntry, '', result);
    }

    return result;
}

export const extractDroppedUploadItems = scanTransferItems;

function buildDirectoryChain(baseDirectory: string, relativeFolderSegments: string[]): string[] {
    const chain: string[] = [];
    let currentPath = baseDirectory;
    for (const segment of relativeFolderSegments) {
        currentPath = currentPath ? `${currentPath}/${segment}` : segment;
        chain.push(currentPath);
    }
    return chain;
}

function resolveFileDestination(
    file: File,
    normalizedBaseDirectory: string
): {
    displayName: string;
    targetPath: string;
    directoryChain: string[];
    validationError?: string;
} {
    const rawFileName = typeof file.name === 'string' ? file.name : '';
    const rawRelativePath = getWebkitRelativePath(file);

    if (rawRelativePath.length > 0) {
        if (
            rawRelativePath.startsWith('/') ||
            rawRelativePath.endsWith('/') ||
            /[\\\0]/.test(rawRelativePath)
        ) {
            return {
                displayName: rawRelativePath || rawFileName || 'unknown',
                targetPath: normalizedBaseDirectory,
                directoryChain: [],
                validationError:
                    'Relative upload path cannot be absolute, end with a slash, or contain backslashes or NUL bytes.',
            };
        }

        const rawSegments = rawRelativePath.split('/');
        if (rawSegments.some((segment) => segment.length === 0)) {
            return {
                displayName: rawRelativePath,
                targetPath: normalizedBaseDirectory,
                directoryChain: [],
                validationError: 'Relative upload path cannot contain empty path segments.',
            };
        }

        for (const segment of rawSegments) {
            const segmentError = validateEntryName(segment);
            if (segmentError) {
                return {
                    displayName: rawRelativePath,
                    targetPath: normalizedBaseDirectory,
                    directoryChain: [],
                    validationError: segmentError,
                };
            }
        }

        const leafSegment = rawSegments[rawSegments.length - 1];
        if (leafSegment !== rawFileName) {
            return {
                displayName: rawRelativePath,
                targetPath: normalizedBaseDirectory,
                directoryChain: [],
                validationError: 'Relative path leaf name must match the File name.',
            };
        }

        let normalizedSubpath = '';
        try {
            normalizedSubpath = normalizeRelativePath(rawRelativePath);
        } catch (err) {
            return {
                displayName: rawRelativePath,
                targetPath: normalizedBaseDirectory,
                directoryChain: [],
                validationError: extractMcBrowserError(err, 'Invalid relative upload path.'),
            };
        }

        let targetPath: string;
        try {
            targetPath = normalizeRelativePath(
                normalizedBaseDirectory
                    ? `${normalizedBaseDirectory}/${normalizedSubpath}`
                    : normalizedSubpath
            );
        } catch (error) {
            return {
                displayName: rawRelativePath,
                targetPath: '',
                directoryChain: [],
                validationError: extractMcBrowserError(
                    error,
                    'Upload path exceeds supported limits.'
                ),
            };
        }
        const folderSegments = rawSegments.slice(0, -1);
        const directoryChain = buildDirectoryChain(normalizedBaseDirectory, folderSegments);

        return {
            displayName: normalizedSubpath,
            targetPath,
            directoryChain,
        };
    }

    const nameError = validateEntryName(rawFileName);
    if (nameError) {
        const fallbackTarget = normalizedBaseDirectory
            ? `${normalizedBaseDirectory}/${rawFileName || 'invalid'}`
            : rawFileName || 'invalid';
        return {
            displayName: rawFileName || 'invalid',
            targetPath: fallbackTarget,
            directoryChain: [],
            validationError: nameError,
        };
    }

    try {
        const targetPath = joinRelativePath(normalizedBaseDirectory, rawFileName);
        return {
            displayName: rawFileName,
            targetPath,
            directoryChain: [],
        };
    } catch (err) {
        const fallbackTarget = normalizedBaseDirectory
            ? `${normalizedBaseDirectory}/${rawFileName}`
            : rawFileName;
        return {
            displayName: rawFileName,
            targetPath: fallbackTarget,
            directoryChain: [],
            validationError: extractMcBrowserError(err, 'Invalid file name.'),
        };
    }
}

function resolveEmptyDirectoryDestination(
    rawRelativeDirectory: string,
    normalizedBaseDirectory: string
): {
    displayName: string;
    targetPath: string;
    directoryChain: string[];
    validationError?: string;
} {
    const rawPath = typeof rawRelativeDirectory === 'string' ? rawRelativeDirectory : '';
    if (!rawPath) {
        return {
            displayName: 'invalid-folder',
            targetPath: normalizedBaseDirectory,
            directoryChain: [],
            validationError: 'Directory path cannot be empty.',
        };
    }

    if (rawPath.startsWith('/') || rawPath.endsWith('/') || /[\\\0]/.test(rawPath)) {
        return {
            displayName: rawPath,
            targetPath: normalizedBaseDirectory,
            directoryChain: [],
            validationError:
                'Relative directory path cannot be absolute, end with a slash, or contain backslashes or NUL bytes.',
        };
    }

    const rawSegments = rawPath.split('/');
    if (rawSegments.some((segment) => segment.length === 0)) {
        return {
            displayName: rawPath,
            targetPath: normalizedBaseDirectory,
            directoryChain: [],
            validationError: 'Relative directory path cannot contain empty path segments.',
        };
    }

    for (const segment of rawSegments) {
        const segmentError = validateEntryName(segment);
        if (segmentError) {
            return {
                displayName: rawPath,
                targetPath: normalizedBaseDirectory,
                directoryChain: [],
                validationError: segmentError,
            };
        }
    }

    let normalizedSubpath = '';
    try {
        normalizedSubpath = normalizeRelativePath(rawPath);
    } catch (err) {
        return {
            displayName: rawPath,
            targetPath: normalizedBaseDirectory,
            directoryChain: [],
            validationError: extractMcBrowserError(err, 'Invalid relative directory path.'),
        };
    }

    let targetPath: string;
    try {
        targetPath = normalizeRelativePath(
            normalizedBaseDirectory
                ? `${normalizedBaseDirectory}/${normalizedSubpath}`
                : normalizedSubpath
        );
    } catch (error) {
        return {
            displayName: rawPath,
            targetPath: '',
            directoryChain: [],
            validationError: extractMcBrowserError(
                error,
                'Directory path exceeds supported limits.'
            ),
        };
    }

    const directoryChain = buildDirectoryChain(normalizedBaseDirectory, rawSegments);
    return {
        displayName: normalizedSubpath,
        targetPath,
        directoryChain,
    };
}

function isBlockingTargetStatus(status: UploadQueueStatus): boolean {
    return (
        status === 'pending' ||
        status === 'pausing' ||
        status === 'cancelling' ||
        status === 'uploading' ||
        status === 'success' ||
        status === 'uncertain'
    );
}

export class McBrowserUploadQueue {
    private readonly uploadFn: UploadQueueTransportFn;
    private readonly cancelSessionFn?: UploadQueueCancelSessionFn;
    private readonly ensureDirectoryFn?: (path: string, signal: AbortSignal) => Promise<unknown>;
    private readonly onChangeFn: (items: UploadQueueItem[]) => void;
    private readonly onIdleFn?: () => void;
    private readonly concurrency: number;
    private readonly maxFiles: number;
    private readonly maxTotalBytes: number;

    private readonly entries: InternalQueueEntry[] = [];
    private readonly ensuredDirectories = new Set<string>();
    private readonly inFlightDirectories = new Map<string, Promise<unknown>>();
    private readonly directoryController = new AbortController();

    private nextSequenceNumber = 1;
    private activeCount = 0;
    private isDisposed = false;
    private isPumping = false;

    constructor(options: McBrowserUploadQueueOptions) {
        this.uploadFn =
            options.upload ??
            ((path, file, signal, onProgress, conflict) =>
                uploadMcBrowserResumable(path, file, { signal, onProgress, conflict }));
        this.cancelSessionFn =
            options.cancelSession ??
            (options.upload === undefined
                ? (path, file, signal, conflict) => cancelMcBrowserResumable(path, file, { signal, conflict })
                : undefined);
        this.ensureDirectoryFn = options.ensureDirectory;
        this.onChangeFn = options.onChange;
        this.onIdleFn = options.onIdle;
        this.concurrency = clampConcurrency(options.concurrency);
        this.maxFiles = normalizePositiveLimit(options.maxFiles, DEFAULT_MAX_UPLOAD_FILES);
        this.maxTotalBytes = normalizePositiveLimit(
            options.maxTotalBytes,
            DEFAULT_MAX_TOTAL_UPLOAD_BYTES
        );
    }

    public enqueue(
        files: File[],
        directory: string,
        maxFileBytes: number,
        emptyDirectories: string[] = []
    ): void {
        if (this.isDisposed) {
            return;
        }
        const safeFiles = Array.isArray(files) ? files : [];
        const safeEmptyDirectories = Array.isArray(emptyDirectories) ? emptyDirectories : [];
        if (safeFiles.length === 0 && safeEmptyDirectories.length === 0) {
            return;
        }

        const normalizedBaseDirectory = normalizeRelativePath(directory);

        let incomingBytes = 0;
        for (const candidateFile of safeFiles) {
            const candidateSize =
                candidateFile &&
                typeof candidateFile.size === 'number' &&
                Number.isFinite(candidateFile.size) &&
                candidateFile.size > 0
                    ? candidateFile.size
                    : 0;
            incomingBytes += candidateSize;
        }

        const incomingCount = safeFiles.length + safeEmptyDirectories.length;
        const currentRetainedCount = this.entries.length;
        const currentRetainedBytes = this.entries.reduce(
            (sumBytes, item) => sumBytes + item.size,
            0
        );

        if (currentRetainedCount + incomingCount > this.maxFiles) {
            throw new McBrowserRequestError(
                400,
                'QUEUE_MAX_FILES_EXCEEDED',
                `Upload queue cannot exceed ${this.maxFiles} files.`
            );
        }

        if (currentRetainedBytes + incomingBytes > this.maxTotalBytes) {
            throw new McBrowserRequestError(
                413,
                'QUEUE_MAX_BYTES_EXCEEDED',
                `Upload queue total size cannot exceed ${formatBytes(this.maxTotalBytes)}.`
            );
        }

        const occupiedTargetPaths = new Set<string>();
        for (const existingEntry of this.entries) {
            if (existingEntry.targetPath && isBlockingTargetStatus(existingEntry.status)) {
                occupiedTargetPaths.add(existingEntry.targetPath);
            }
        }

        const retireSupersededEntriesForPath = (targetPath: string) => {
            if (!targetPath) {
                return;
            }
            for (const existingEntry of this.entries) {
                if (
                    existingEntry.targetPath === targetPath &&
                    (existingEntry.status === 'error' ||
                        existingEntry.status === 'cancelled' ||
                        existingEntry.status === 'paused')
                ) {
                    existingEntry.file = null;
                    existingEntry.canRetryDirectory = false;
                }
            }
        };

        for (const rawEmptyDir of safeEmptyDirectories) {
            const entryId = `upload-${this.nextSequenceNumber}`;
            this.nextSequenceNumber += 1;

            const resolvedDir = resolveEmptyDirectoryDestination(
                rawEmptyDir,
                normalizedBaseDirectory
            );

            if (resolvedDir.validationError) {
                this.entries.push({
                    id: entryId,
                    name: resolvedDir.displayName,
                    targetPath: resolvedDir.targetPath,
                    directoryChain: resolvedDir.directoryChain,
                    size: 0,
                    uploadedBytes: 0,
                    speedBytesPerSecond: 0,
                    kind: 'directory',
                    status: 'error',
                    error: resolvedDir.validationError,
                    file: null,
                    canRetryDirectory: false,
                    maxFileBytes,
                    controller: null,
                    uploadStarted: false,
                    cancelRequested: false,
                    pauseRequested: false,
                });
                continue;
            }

            if (occupiedTargetPaths.has(resolvedDir.targetPath)) {
                this.entries.push({
                    id: entryId,
                    name: resolvedDir.displayName,
                    targetPath: resolvedDir.targetPath,
                    directoryChain: resolvedDir.directoryChain,
                    size: 0,
                    uploadedBytes: 0,
                    speedBytesPerSecond: 0,
                    kind: 'directory',
                    status: 'error',
                    error: `Duplicate upload destination "${resolvedDir.targetPath}" in queue.`,
                    file: null,
                    canRetryDirectory: false,
                    maxFileBytes,
                    controller: null,
                    uploadStarted: false,
                    cancelRequested: false,
                    pauseRequested: false,
                });
                continue;
            }

            retireSupersededEntriesForPath(resolvedDir.targetPath);
            occupiedTargetPaths.add(resolvedDir.targetPath);

            this.entries.push({
                id: entryId,
                name: resolvedDir.displayName,
                targetPath: resolvedDir.targetPath,
                directoryChain: resolvedDir.directoryChain,
                size: 0,
                uploadedBytes: 0,
                speedBytesPerSecond: 0,
                kind: 'directory',
                status: 'pending',
                file: null,
                canRetryDirectory: true,
                maxFileBytes,
                controller: null,
                uploadStarted: false,
                cancelRequested: false,
                pauseRequested: false,
            });
        }

        for (const incomingFile of safeFiles) {
            const entryId = `upload-${this.nextSequenceNumber}`;
            this.nextSequenceNumber += 1;

            const safeSize =
                typeof incomingFile.size === 'number' &&
                Number.isFinite(incomingFile.size) &&
                incomingFile.size >= 0
                    ? incomingFile.size
                    : 0;

            const resolved = resolveFileDestination(incomingFile, normalizedBaseDirectory);

            if (resolved.validationError) {
                this.entries.push({
                    id: entryId,
                    name: resolved.displayName,
                    targetPath: resolved.targetPath,
                    directoryChain: resolved.directoryChain,
                    size: safeSize,
                    uploadedBytes: 0,
                    speedBytesPerSecond: 0,
                    kind: 'file',
                    status: 'error',
                    error: resolved.validationError,
                    file: null,
                    canRetryDirectory: false,
                    maxFileBytes,
                    controller: null,
                    uploadStarted: false,
                    cancelRequested: false,
                    pauseRequested: false,
                });
                continue;
            }

            if (occupiedTargetPaths.has(resolved.targetPath)) {
                this.entries.push({
                    id: entryId,
                    name: resolved.displayName,
                    targetPath: resolved.targetPath,
                    directoryChain: resolved.directoryChain,
                    size: safeSize,
                    uploadedBytes: 0,
                    speedBytesPerSecond: 0,
                    kind: 'file',
                    status: 'error',
                    error: `Duplicate upload destination "${resolved.targetPath}" in queue.`,
                    file: null,
                    canRetryDirectory: false,
                    maxFileBytes,
                    controller: null,
                    uploadStarted: false,
                    cancelRequested: false,
                    pauseRequested: false,
                });
                continue;
            }

            retireSupersededEntriesForPath(resolved.targetPath);
            occupiedTargetPaths.add(resolved.targetPath);

            if (maxFileBytes > 0 && safeSize > maxFileBytes) {
                this.entries.push({
                    id: entryId,
                    name: resolved.displayName,
                    targetPath: resolved.targetPath,
                    directoryChain: resolved.directoryChain,
                    size: safeSize,
                    uploadedBytes: 0,
                    speedBytesPerSecond: 0,
                    kind: 'file',
                    status: 'error',
                    error: `File exceeds maximum upload limit of ${formatBytes(maxFileBytes)}.`,
                    file: incomingFile,
                    canRetryDirectory: false,
                    maxFileBytes,
                    controller: null,
                    uploadStarted: false,
                    cancelRequested: false,
                    pauseRequested: false,
                });
                continue;
            }

            this.entries.push({
                id: entryId,
                name: resolved.displayName,
                targetPath: resolved.targetPath,
                directoryChain: resolved.directoryChain,
                size: safeSize,
                uploadedBytes: 0,
                speedBytesPerSecond: 0,
                kind: 'file',
                status: 'pending',
                file: incomingFile,
                canRetryDirectory: false,
                maxFileBytes,
                controller: null,
                uploadStarted: false,
                cancelRequested: false,
                pauseRequested: false,
            });
        }

        this.emitChange();
        this.pump();
    }

    public pause(id?: string): void {
        if (this.isDisposed) {
            return;
        }

        let mutated = false;

        for (const entry of this.entries) {
            if (id !== undefined && entry.id !== id) {
                continue;
            }

            if (entry.status === 'pending') {
                entry.status = 'paused';
                entry.resumeRequested = false;
                entry.pauseRequested = true;
                entry.cancelRequested = false;
                delete entry.error;
                mutated = true;
            } else if (entry.status === 'uploading') {
                entry.status = 'pausing';
                entry.resumeRequested = false;
                entry.pauseRequested = true;
                entry.cancelRequested = false;
                delete entry.error;
                if (entry.controller) {
                    entry.controller.abort();
                }
                mutated = true;
            }
        }

        if (mutated) {
            this.emitChange();
            this.pump();
        }
    }

    public resume(id?: string): void {
        if (this.isDisposed) {
            return;
        }

        const activeTargetPaths = new Set<string>();
        for (const entry of this.entries) {
            if (isBlockingTargetStatus(entry.status) && entry.targetPath) {
                activeTargetPaths.add(entry.targetPath);
            }
        }

        let mutated = false;

        for (const entry of this.entries) {
            if (id !== undefined && entry.id !== id) {
                continue;
            }
            if (entry.status === 'pausing') {
                entry.resumeRequested = true;
                mutated = true;
                continue;
            }
            if (entry.status !== 'paused') {
                continue;
            }
            if (entry.kind === 'file' && !entry.file) {
                continue;
            }
            if (entry.kind === 'directory' && !entry.canRetryDirectory) {
                continue;
            }

            if (activeTargetPaths.has(entry.targetPath)) {
                entry.status = 'error';
                entry.error = `Duplicate upload destination "${entry.targetPath}" in queue.`;
                mutated = true;
                continue;
            }

            activeTargetPaths.add(entry.targetPath);
            entry.status = 'pending';
            entry.pauseRequested = false;
            entry.cancelRequested = false;
            delete entry.error;
            mutated = true;
        }

        if (mutated) {
            this.emitChange();
            this.pump();
        }
    }

    public cancel(id?: string): void {
        if (this.isDisposed) {
            return;
        }

        let mutated = false;

        for (const entry of this.entries) {
            if (id !== undefined && entry.id !== id) {
                continue;
            }

            entry.resumeRequested = false;

            if (entry.status === 'pending') {
                entry.status = 'cancelled';
                entry.error = 'Upload cancelled.';
                entry.cancelRequested = false;
                entry.pauseRequested = false;
                mutated = true;
            } else if (entry.status === 'paused') {
                entry.pauseRequested = false;
                entry.cancelRequested = true;
                if (entry.uploadStarted || entry.uploadedBytes > 0) {
                    if (this.cancelSessionFn && entry.file) {
                        entry.status = 'cancelling';
                        entry.error = 'Confirming server cancellation...';
                        void this.terminateRemoteSession(entry, entry.file);
                    } else {
                        entry.status = 'uncertain';
                        entry.error =
                            'Upload interrupted; destination state could not be verified.';
                        entry.file = null;
                        entry.canRetryDirectory = false;
                    }
                } else {
                    entry.status = 'cancelled';
                    entry.error = 'Upload cancelled.';
                }
                mutated = true;
            } else if (entry.status === 'uploading' || entry.status === 'pausing') {
                entry.pauseRequested = false;
                entry.cancelRequested = true;

                if (!entry.uploadStarted) {
                    entry.status = 'cancelled';
                    entry.error = 'Upload cancelled.';
                } else if (this.cancelSessionFn && entry.file) {
                    entry.status = 'cancelling';
                    entry.error = 'Confirming server cancellation...';
                } else {
                    entry.status = 'uncertain';
                    entry.error = 'Upload interrupted; destination state could not be verified.';
                    entry.file = null;
                    entry.canRetryDirectory = false;
                }

                if (entry.controller) {
                    entry.controller.abort();
                }
                mutated = true;
            }
        }

        if (mutated) {
            this.emitChange();
            this.pump();
        }
    }

    public retryFailed(): void {
        if (this.isDisposed) {
            return;
        }

        const activeTargetPaths = new Set<string>();
        for (const entry of this.entries) {
            if (isBlockingTargetStatus(entry.status) && entry.targetPath) {
                activeTargetPaths.add(entry.targetPath);
            }
        }

        let mutated = false;

        for (const entry of this.entries) {
            if (entry.controller || (entry.status !== 'error' && entry.status !== 'cancelled')) {
                continue;
            }

            if (entry.kind === 'file' && !entry.file) {
                continue;
            }
            if (entry.kind === 'directory' && !entry.canRetryDirectory) {
                continue;
            }

            if (
                entry.kind === 'file' &&
                entry.maxFileBytes > 0 &&
                entry.size > entry.maxFileBytes
            ) {
                const limitMessage = `File exceeds maximum upload limit of ${formatBytes(entry.maxFileBytes)}.`;
                if (entry.status !== 'error' || entry.error !== limitMessage) {
                    entry.status = 'error';
                    entry.error = limitMessage;
                    mutated = true;
                }
                continue;
            }

            if (activeTargetPaths.has(entry.targetPath)) {
                const duplicateMessage = `Duplicate upload destination "${entry.targetPath}" in queue.`;
                if (entry.status !== 'error' || entry.error !== duplicateMessage) {
                    entry.status = 'error';
                    entry.error = duplicateMessage;
                    mutated = true;
                }
                continue;
            }

            activeTargetPaths.add(entry.targetPath);
            entry.status = 'pending';
            delete entry.error;
            entry.cancelRequested = false;
            entry.pauseRequested = false;
            entry.uploadStarted = false;
            entry.controller = null;
            mutated = true;
        }

        if (mutated) {
            this.emitChange();
            this.pump();
        }
    }

    public resolveConflict(id: string, conflict: 'overwrite' | 'skip' | 'resume'): void {
        if (this.isDisposed || !['overwrite', 'skip', 'resume'].includes(conflict)) return;
        const entry = this.entries.find((candidate) => candidate.id === id);
        if (!entry || entry.controller || entry.status !== 'error' || !entry.conflictDetected || !entry.file) return;
        if (this.entries.some((candidate) => candidate !== entry && candidate.targetPath === entry.targetPath && isBlockingTargetStatus(candidate.status))) return;
        entry.conflict = conflict;
        entry.conflictDetected = false;
        entry.status = 'pending';
        entry.uploadStarted = false;
        entry.cancelRequested = false;
        entry.pauseRequested = false;
        delete entry.error;
        this.emitChange();
        this.pump();
    }

    public clearCompleted(): void {
        if (this.isDisposed) {
            return;
        }

        const previousLength = this.entries.length;
        for (let index = this.entries.length - 1; index >= 0; index -= 1) {
            if (
                !this.entries[index].controller &&
                this.entries[index].status !== 'pending' &&
                this.entries[index].status !== 'uploading' &&
                this.entries[index].status !== 'paused' &&
                this.entries[index].status !== 'pausing' &&
                this.entries[index].status !== 'cancelling'
            ) {
                this.entries.splice(index, 1);
            }
        }

        if (this.entries.length !== previousLength) {
            this.emitChange();
        }
    }

    public dispose(): void {
        if (this.isDisposed) {
            return;
        }
        this.isDisposed = true;
        this.directoryController.abort();

        for (const entry of this.entries) {
            if (entry.controller) {
                entry.controller.abort();
                entry.controller = null;
            }
            entry.file = null;
            entry.canRetryDirectory = false;
        }

        this.inFlightDirectories.clear();
    }

    public snapshot(): UploadQueueItem[] {
        return this.entries.map((entry) => {
            const snapshotItem: UploadQueueItem = {
                id: entry.id,
                name: entry.name,
                targetPath: entry.targetPath,
                size: entry.size,
                status: entry.status,
                uploadedBytes: entry.uploadedBytes,
                speedBytesPerSecond: entry.speedBytesPerSecond,
                kind: entry.kind,
                conflictDetected: entry.conflictDetected,
                skipped: entry.skipped,
            };
            if (entry.error !== undefined) {
                snapshotItem.error = entry.error;
            }
            return Object.freeze(snapshotItem);
        });
    }

    private emitChange(): void {
        if (this.isDisposed) {
            return;
        }
        this.onChangeFn(this.snapshot());
    }

    private emitIdleIfDrained(): void {
        if (this.isDisposed) {
            return;
        }
        if (this.activeCount > 0) {
            return;
        }
        const hasPending = this.entries.some((entry) => entry.status === 'pending' || entry.status === 'pausing' || entry.status === 'cancelling');
        if (!hasPending) {
            this.ensuredDirectories.clear();
            this.onIdleFn?.();
        }
    }

    private pump(): void {
        if (this.isDisposed || this.isPumping) {
            return;
        }
        this.isPumping = true;
        try {
            while (!this.isDisposed && this.activeCount < this.concurrency) {
                const nextEntry = this.entries.find((entry) => entry.status === 'pending' && !entry.controller);
                if (!nextEntry) {
                    break;
                }
                this.startEntry(nextEntry);
            }
        } finally {
            this.isPumping = false;
        }
    }

    private startEntry(entry: InternalQueueEntry): void {
        if (entry.kind === 'file' && !entry.file) {
            entry.status = 'error';
            entry.error = 'Upload file reference is no longer available.';
            this.emitChange();
            return;
        }

        const controller = new AbortController();
        entry.controller = controller;
        entry.status = 'uploading';
        entry.uploadStarted = false;
        entry.cancelRequested = false;
        entry.pauseRequested = false;
        delete entry.error;
        this.activeCount += 1;
        this.emitChange();

        void this.executeEntry(entry, controller);
    }

    private async terminateRemoteSession(entry: InternalQueueEntry, file: File): Promise<void> {
        if (!this.cancelSessionFn) {
            return;
        }
        try {
            const res = await this.cancelSessionFn(entry.targetPath, file, undefined, entry.conflict);
            if (this.isDisposed) {
                return;
            }
            const cancelled =
                res && typeof res === 'object' && 'cancelled' in res
                    ? Boolean((res as { cancelled?: unknown }).cancelled)
                    : true;
            if (!cancelled && (entry.uploadStarted || entry.uploadedBytes > 0)) {
                entry.status = 'uncertain';
                entry.error = 'Upload interrupted; destination state could not be verified.';
                entry.file = null;
                entry.canRetryDirectory = false;
            } else {
                entry.status = 'cancelled';
                entry.error = 'Upload cancelled.';
                entry.uploadedBytes = 0;
                entry.speedBytesPerSecond = 0;
            }
        } catch (cancelErr) {
            if (this.isDisposed) {
                return;
            }
            entry.status = 'uncertain';
            entry.error = extractMcBrowserError(
                cancelErr,
                'Upload interrupted; destination state could not be verified.'
            );
            entry.file = null;
            entry.canRetryDirectory = false;
        }
        this.emitChange();
        this.emitIdleIfDrained();
    }

    private async ensureDirectoryHierarchy(
        directoryChain: string[],
        entry: InternalQueueEntry,
        entrySignal: AbortSignal
    ): Promise<void> {
        if (!this.ensureDirectoryFn || directoryChain.length === 0) {
            return;
        }

        for (const directoryPath of directoryChain) {
            if (
                this.isDisposed ||
                entry.cancelRequested ||
                entry.pauseRequested ||
                entrySignal.aborted
            ) {
                throw new Error('Upload aborted during directory preparation.');
            }

            if (this.ensuredDirectories.has(directoryPath)) {
                continue;
            }

            let pendingPromise = this.inFlightDirectories.get(directoryPath);
            if (!pendingPromise) {
                const creationPromise = Promise.resolve()
                    .then(() =>
                        this.ensureDirectoryFn!(directoryPath, this.directoryController.signal)
                    )
                    .then(
                        (result) => {
                            this.inFlightDirectories.delete(directoryPath);
                            if (!this.isDisposed && !this.directoryController.signal.aborted) {
                                this.ensuredDirectories.add(directoryPath);
                            }
                            return result;
                        },
                        (error) => {
                            this.inFlightDirectories.delete(directoryPath);
                            throw error;
                        }
                    );
                this.inFlightDirectories.set(directoryPath, creationPromise);
                pendingPromise = creationPromise;
            }

            await waitForDirectoryPreparation(pendingPromise, entrySignal);
        }
    }

    private async executeEntry(
        entry: InternalQueueEntry,
        controller: AbortController
    ): Promise<void> {
        const fileReference = entry.file;
        try {
            if (entry.kind === 'file' && !fileReference) {
                throw new Error('Upload file reference is missing.');
            }

            await this.ensureDirectoryHierarchy(entry.directoryChain, entry, controller.signal);

            if (this.isDisposed) {
                return;
            }

            if (entry.pauseRequested) {
                entry.status = 'paused';
                delete entry.error;
                return;
            }

            if (entry.cancelRequested || controller.signal.aborted) {
                entry.status = 'cancelled';
                entry.error = 'Upload cancelled.';
                return;
            }

            if (entry.kind === 'directory') {
                entry.status = 'success';
                delete entry.error;
                entry.cancelRequested = false;
                entry.pauseRequested = false;
                entry.canRetryDirectory = false;
                return;
            }

            entry.uploadStarted = true;
            const uploadResult = await this.uploadFn(
                entry.targetPath,
                fileReference!,
                controller.signal,
                (progress) => {
                    if (this.isDisposed || entry.status !== 'uploading') {
                        return;
                    }
                    if (
                        typeof progress.uploadedBytes === 'number' &&
                        Number.isFinite(progress.uploadedBytes)
                    ) {
                        entry.uploadedBytes = Math.min(
                            Math.max(0, Math.trunc(progress.uploadedBytes)),
                            entry.size
                        );
                    }
                    if (
                        typeof progress.speedBytesPerSecond === 'number' &&
                        Number.isFinite(progress.speedBytesPerSecond)
                    ) {
                        entry.speedBytesPerSecond = Math.max(
                            0,
                            Math.trunc(progress.speedBytesPerSecond)
                        );
                    }
                    this.emitChange();
                },
                entry.conflict
            );

            if (this.isDisposed) {
                return;
            }

            if (
                uploadResult &&
                typeof uploadResult === 'object' &&
                'path' in uploadResult &&
                typeof (uploadResult as { path?: unknown }).path === 'string' &&
                (uploadResult as { path: string }).path.trim()
            ) {
                entry.targetPath = normalizeRelativePath((uploadResult as { path: string }).path);
            }

            entry.status = 'success';
            entry.skipped = Boolean(uploadResult && typeof uploadResult === 'object' && 'skipped' in uploadResult && uploadResult.skipped === true);
            entry.conflictDetected = false;
            entry.uploadedBytes = entry.size;
            entry.speedBytesPerSecond = 0;
            delete entry.error;
            entry.cancelRequested = false;
            entry.pauseRequested = false;
            entry.file = null;
        } catch (err) {
            if (this.isDisposed) {
                return;
            }

            if (isMcBrowserUploadUncertainError(err)) {
                entry.status = 'uncertain';
                entry.error = extractMcBrowserError(
                    err,
                    'Upload interrupted; destination state could not be verified.'
                );
                entry.file = null;
                entry.canRetryDirectory = false;
                return;
            }

            if (entry.pauseRequested) {
                entry.status = 'paused';
                entry.speedBytesPerSecond = 0;
                delete entry.error;
                return;
            }

            if (entry.cancelRequested || controller.signal.aborted) {
                if (!entry.uploadStarted) {
                    entry.status = 'cancelled';
                    entry.error = 'Upload cancelled.';
                    return;
                }

                if (this.cancelSessionFn && fileReference) {
                    await this.terminateRemoteSession(entry, fileReference);
                    return;
                }

                entry.status = 'uncertain';
                entry.error = 'Upload interrupted; destination state could not be verified.';
                entry.file = null;
                entry.canRetryDirectory = false;
                return;
            }

            if (entry.uploadStarted && !(err instanceof McBrowserRequestError)) {
                entry.status = 'uncertain';
                entry.error = 'Upload interrupted; destination state could not be verified.';
                entry.file = null;
                entry.canRetryDirectory = false;
            } else {
                entry.status = 'error';
                entry.speedBytesPerSecond = 0;
                entry.error = extractMcBrowserError(err, 'Failed to upload file.');
                entry.conflictDetected = err instanceof McBrowserRequestError && err.status === 409;
            }
        } finally {
            entry.controller = null;
            this.activeCount = Math.max(0, this.activeCount - 1);

            if (entry.resumeRequested && entry.status === 'paused' && !entry.cancelRequested) {
                entry.status = 'pending';
                entry.pauseRequested = false;
                entry.resumeRequested = false;
            }

            if (!this.isDisposed) {
                this.emitChange();
                this.pump();
                this.emitIdleIfDrained();
            }
        }
    }
}
