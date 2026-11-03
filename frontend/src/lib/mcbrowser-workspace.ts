import { apiFetch } from '@/lib/fetcher';
import {
    MCBROWSER_BASE,
    McBrowserConflictPolicy,
    McBrowserConflictPolicyInput,
    McBrowserCopyMoveOptions,
    McBrowserCopyMoveResponse,
    McBrowserEntry,
    McBrowserRequestError,
    McBrowserSuccessResponse,
    mcbrowserJsonRequest,
    normalizeMcBrowserConflictPolicy,
    normalizeRelativePath,
    navigateMcBrowserDownload,
    parseFilenameFromContentDisposition,
    resolveMcBrowserCopyMoveCallOptions,
} from '@/lib/mcbrowser';

export type {
    McBrowserConflictPolicy,
    McBrowserConflictPolicyInput,
    McBrowserCopyMoveOptions,
    McBrowserCopyMoveResponse,
};
export { normalizeMcBrowserConflictPolicy };

export type McBrowserSearchType = '' | 'all' | 'file' | 'directory';
export type McBrowserChecksumAlgorithm = 'sha256' | 'md5' | 'sha1' | 'sha512';
export type McBrowserArchiveFormat = 'zip' | 'tar' | 'tar.gz' | 'targz' | 'tarbz2' | 'tarxz' | 'tarlz4' | 'tarsz' | 'tarbr' | 'tarzst';
export type McBrowserViewMode =
    | 'list'
    | 'grid'
    | 'gallery'
    | 'mosaic'
    | 'mosaic gallery'
    | 'mosaic_gallery';
export type McBrowserSortField = 'name' | 'size' | 'modified';
export type McBrowserSortDirection = 'asc' | 'desc';

export interface McBrowserSearchResponse {
    entries: McBrowserEntry[];
    truncated: boolean;
    ai_interpretation?: string;
    ai_powered?: boolean;
}

export interface McBrowserContentResponse {
    path: string;
    content: string;
    etag: string;
}

export interface McBrowserSaveContentResponse {
    success: boolean;
    etag: string;
    accounting_pending?: boolean;
}

export interface McBrowserFileInfoResponse {
    entry: McBrowserEntry;
    checksums: Partial<Record<McBrowserChecksumAlgorithm, string>>;
    num_files?: number | null;
    num_dirs?: number | null;
}

export interface McBrowserShareItem {
    id: string;
    path: string;
    expires_at: string | null;
    allow_download: boolean;
    created_at: string;
    url: string;
}

export interface McBrowserSharesListResponse {
    shares: McBrowserShareItem[];
}

export interface McBrowserCreateSharePayload {
    path: string;
    password?: string;
    expires_at?: string;
    allow_download?: boolean;
}

export interface McBrowserCreateShareResponse {
    share: McBrowserShareItem;
}

export interface McBrowserPolicyPermissions {
    read: boolean;
    create: boolean;
    rename: boolean;
    modify: boolean;
    delete: boolean;
    share: boolean;
    download: boolean;
    execute?: boolean;
}

export interface McBrowserPolicyRule {
    id?: string;
    pattern?: string;
    description?: string;
    effect?: string;
    [key: string]: unknown;
}

export interface McBrowserPolicyResponse {
    permissions: McBrowserPolicyPermissions;
    rules: McBrowserPolicyRule[];
    scope: string;
}

export interface McBrowserPreferences {
    view: McBrowserViewMode;
    sort: McBrowserSortField;
    direction: McBrowserSortDirection;
    show_hidden: boolean;
    single_click: boolean;
    natural_sort?: boolean;
    redirect_after_copy_move?: boolean;
    date_format?: boolean;
    editor_theme?: string;
    locale: string;
}

export function normalizeMcBrowserViewMode(
    view?: McBrowserViewMode | string
): 'list' | 'grid' | 'gallery' {
    if (view === 'grid' || view === 'mosaic') {
        return 'grid';
    }
    if (view === 'gallery' || view === 'mosaic gallery' || view === 'mosaic_gallery') {
        return 'gallery';
    }
    return 'list';
}

export function normalizeMcBrowserPreferences(
    raw?: Partial<McBrowserPreferences> | null
): Required<McBrowserPreferences> {
    return {
        view: normalizeMcBrowserViewMode(raw?.view),
        sort: raw?.sort === 'size' || raw?.sort === 'modified' ? raw.sort : 'name',
        direction: raw?.direction === 'desc' ? 'desc' : 'asc',
        show_hidden: Boolean(raw?.show_hidden),
        single_click: Boolean(raw?.single_click),
        natural_sort: raw?.natural_sort !== false,
        redirect_after_copy_move: Boolean(raw?.redirect_after_copy_move),
        date_format: Boolean(raw?.date_format),
        editor_theme:
            typeof raw?.editor_theme === 'string' && raw.editor_theme.trim()
                ? raw.editor_theme.trim()
                : 'chrome',
        locale:
            typeof raw?.locale === 'string' && raw.locale.trim()
                ? raw.locale.trim()
                : 'en-US',
    };
}

export interface McBrowserUsageResponse {
    used_bytes: number;
    quota_bytes: number;
    status: string;
}

export interface McBrowserBatchItemOutcome {
    path: string;
    destinationPath?: string;
    status: 'success' | 'conflict' | 'forbidden' | 'error';
    code?: string;
    message?: string;
}

export interface McBrowserArchiveDownloadResult {
    filename: string;
    bytesWritten: number;
    method: 'filesystem-access' | 'bounded-blob' | 'browser-navigation';
}

export const MAX_ARCHIVE_BLOB_FALLBACK_BYTES = 128 * 1024 * 1024; // 128 MiB

interface FileSystemWritableStreamLike {
    write(chunk: Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort?(reason?: unknown): Promise<void>;
}

interface FileSystemFileHandleLike {
    createWritable(): Promise<FileSystemWritableStreamLike>;
}

export type SaveFilePickerFn = (options?: {
    suggestedName?: string;
}) => Promise<FileSystemFileHandleLike>;

async function parseWorkspaceErrorResponse(
    res: Response,
    fallbackMessage: string
): Promise<McBrowserRequestError> {
    let body: unknown = null;
    try {
        body = await res.json();
    } catch {
        body = null;
    }

    const errObj = (body && typeof body === 'object' ? body : {}) as {
        code?: unknown;
        message?: unknown;
        error?: unknown;
        details?: unknown;
    };

    const code =
        typeof errObj.code === 'string' && errObj.code.trim()
            ? errObj.code.trim()
            : `HTTP_${res.status}`;
    const message =
        (typeof errObj.message === 'string' && errObj.message.trim()) ||
        (typeof errObj.error === 'string' && errObj.error.trim()) ||
        fallbackMessage ||
        `Request failed (${res.status} ${res.statusText || 'Error'})`;

    return new McBrowserRequestError(res.status, code, message, errObj.details);
}

export async function searchMcBrowserEntries(
    params: {
        path?: string;
        q: string;
        type?: McBrowserSearchType | string;
        ai?: boolean;
    },
    signal?: AbortSignal
): Promise<McBrowserSearchResponse> {
    const normalizedPath = normalizeRelativePath(params.path ?? '');
    const trimmedQuery = params.q.trim();
    if (!trimmedQuery) {
        throw new McBrowserRequestError(400, 'INVALID_QUERY', 'Search query cannot be empty.');
    }
    const rawType = (params.type ?? '').trim();
    const searchType = rawType === 'all' ? '' : rawType;
    const aiParam = params.ai ? '&ai=true' : '';
    const qs = `?path=${encodeURIComponent(normalizedPath)}&q=${encodeURIComponent(trimmedQuery)}&type=${encodeURIComponent(searchType)}${aiParam}`;
    return mcbrowserJsonRequest<McBrowserSearchResponse>(
        `${MCBROWSER_BASE}/search${qs}`,
        { method: 'GET', signal },
        'Failed to search files.'
    );
}

export async function copyMcBrowserEntry(
    fromPath: string,
    toPath: string,
    optionsOrConflict?: McBrowserConflictPolicyInput | McBrowserCopyMoveOptions | AbortSignal,
    signal?: AbortSignal
): Promise<McBrowserCopyMoveResponse> {
    const normalizedFrom = normalizeRelativePath(fromPath);
    const normalizedTo = normalizeRelativePath(toPath);
    if (!normalizedFrom || !normalizedTo) {
        throw new McBrowserRequestError(
            400,
            'INVALID_PATH',
            'Source and destination relative paths are required for copy.'
        );
    }
    const resolved = resolveMcBrowserCopyMoveCallOptions(optionsOrConflict, signal);
    const payload: { from: string; to: string; conflict?: McBrowserConflictPolicy } = {
        from: normalizedFrom,
        to: normalizedTo,
    };
    if (resolved.conflict) {
        payload.conflict = resolved.conflict;
    }
    return mcbrowserJsonRequest<McBrowserCopyMoveResponse>(
        `${MCBROWSER_BASE}/copy`,
        {
            method: 'POST',
            body: JSON.stringify(payload),
            ...(resolved.signal ? { signal: resolved.signal } : {}),
        },
        'Failed to copy entry.'
    );
}

export async function deleteMcBrowserRecursive(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Cannot recursively delete root directory.');
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/delete-recursive`,
        {
            method: 'POST',
            body: JSON.stringify({ path: normalized }),
            signal,
        },
        'Failed to recursively delete entry.'
    );
}

export async function fetchMcBrowserContent(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserContentResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'File path is required to load content.');
    }
    return mcbrowserJsonRequest<McBrowserContentResponse>(
        `${MCBROWSER_BASE}/content?path=${encodeURIComponent(normalized)}`,
        { method: 'GET', signal },
        'Failed to load file content.'
    );
}

export async function saveMcBrowserContent(
    relativePath: string,
    content: string,
    etag: string,
    signal?: AbortSignal
): Promise<McBrowserSaveContentResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'File path is required to save content.');
    }
    if (!etag || !etag.trim()) {
        throw new McBrowserRequestError(
            400,
            'MISSING_ETAG',
            'Optimistic concurrency ETag is required to save file changes.'
        );
    }
    return mcbrowserJsonRequest<McBrowserSaveContentResponse>(
        `${MCBROWSER_BASE}/content?path=${encodeURIComponent(normalized)}`,
        {
            method: 'PUT',
            body: JSON.stringify({ content, etag }),
            signal,
        },
        'Failed to save file content.'
    );
}

export async function createMcBrowserFile(
    relativePath: string,
    content?: string,
    signal?: AbortSignal
): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'File path is required to create a file.');
    }
    const payload: { path: string; content?: string } = { path: normalized };
    if (typeof content === 'string') {
        payload.content = content;
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/file`,
        {
            method: 'POST',
            body: JSON.stringify(payload),
            signal,
        },
        'Failed to create file.'
    );
}

export async function fetchMcBrowserFileInfo(
    relativePath: string,
    checksum: McBrowserChecksumAlgorithm | null = 'sha256',
    signal?: AbortSignal
): Promise<McBrowserFileInfoResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Path is required for file info.');
    }
    const qs = `?path=${encodeURIComponent(normalized)}${checksum ? `&checksum=${encodeURIComponent(checksum)}` : ''}`;
    return mcbrowserJsonRequest<McBrowserFileInfoResponse>(
        `${MCBROWSER_BASE}/info${qs}`,
        { method: 'GET', signal },
        'Failed to fetch file info and checksum.'
    );
}

export async function listMcBrowserShares(
    signal?: AbortSignal
): Promise<McBrowserSharesListResponse> {
    return mcbrowserJsonRequest<McBrowserSharesListResponse>(
        `${MCBROWSER_BASE}/shares`,
        { method: 'GET', signal },
        'Failed to load share links.'
    );
}

export async function createMcBrowserShare(
    payload: McBrowserCreateSharePayload,
    signal?: AbortSignal
): Promise<McBrowserCreateShareResponse> {
    const normalized = normalizeRelativePath(payload.path);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Target path is required to create a share link.');
    }
    const body: McBrowserCreateSharePayload = {
        path: normalized,
    };
    if (payload.password && payload.password.trim()) {
        body.password = payload.password;
    }
    if (payload.expires_at && payload.expires_at.trim()) {
        body.expires_at = payload.expires_at.trim();
    }
    if (typeof payload.allow_download === 'boolean') {
        body.allow_download = payload.allow_download;
    }
    return mcbrowserJsonRequest<McBrowserCreateShareResponse>(
        `${MCBROWSER_BASE}/shares`,
        {
            method: 'POST',
            body: JSON.stringify(body),
            signal,
        },
        'Failed to create share link.'
    );
}

export async function revokeMcBrowserShare(
    shareId: string,
    signal?: AbortSignal
): Promise<McBrowserSuccessResponse> {
    const trimmed = shareId.trim();
    if (!trimmed || /[\\/\0]/.test(trimmed)) {
        throw new McBrowserRequestError(400, 'INVALID_SHARE_ID', 'Valid share ID is required.');
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/shares/${encodeURIComponent(trimmed)}`,
        {
            method: 'DELETE',
            signal,
        },
        'Failed to revoke share link.'
    );
}

export async function fetchMcBrowserPolicy(
    signal?: AbortSignal
): Promise<McBrowserPolicyResponse> {
    return mcbrowserJsonRequest<McBrowserPolicyResponse>(
        `${MCBROWSER_BASE}/policy`,
        { method: 'GET', signal },
        'Failed to fetch workspace access policy.'
    );
}

export async function fetchMcBrowserPreferences(
    signal?: AbortSignal
): Promise<McBrowserPreferences> {
    const raw = await mcbrowserJsonRequest<McBrowserPreferences>(
        `${MCBROWSER_BASE}/preferences`,
        { method: 'GET', signal },
        'Failed to fetch workspace preferences.'
    );
    return normalizeMcBrowserPreferences(raw);
}

export async function updateMcBrowserPreferences(
    preferences: McBrowserPreferences,
    signal?: AbortSignal
): Promise<McBrowserPreferences> {
    const normalizedPayload = normalizeMcBrowserPreferences(preferences);
    const saved = await mcbrowserJsonRequest<McBrowserPreferences>(
        `${MCBROWSER_BASE}/preferences`,
        {
            method: 'PUT',
            body: JSON.stringify(normalizedPayload),
            signal,
        },
        'Failed to save workspace preferences.'
    );
    return normalizeMcBrowserPreferences(saved);
}

export async function fetchMcBrowserUsage(
    signal?: AbortSignal
): Promise<McBrowserUsageResponse> {
    return mcbrowserJsonRequest<McBrowserUsageResponse>(
        `${MCBROWSER_BASE}/usage`,
        { method: 'GET', signal },
        'Failed to fetch storage usage.'
    );
}

export function classifyBatchError(err: unknown): {
    status: 'conflict' | 'forbidden' | 'error';
    code: string;
    message: string;
} {
    if (err instanceof McBrowserRequestError) {
        if (err.status === 409 || /CONFLICT|EXISTS/i.test(err.code)) {
            return { status: 'conflict', code: err.code, message: err.message };
        }
        if (err.status === 403 || /FORBIDDEN|DENIED|POLICY/i.test(err.code)) {
            return { status: 'forbidden', code: err.code, message: err.message };
        }
        return { status: 'error', code: err.code, message: err.message };
    }
    if (err instanceof Error) {
        return { status: 'error', code: 'ERROR', message: err.message };
    }
    return { status: 'error', code: 'UNKNOWN_ERROR', message: 'Operation failed.' };
}

export function resolveBatchDestinationPath(
    sourcePath: string,
    destinationDirInput: string,
    conflictPolicy: McBrowserConflictPolicy = 'error'
): string {
    const normalizedSource = normalizeRelativePath(sourcePath);
    if (!normalizedSource) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Source path cannot be empty.');
    }
    const baseName = normalizedSource.split('/').pop() || '';
    if (!baseName) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Source entry name could not be resolved.');
    }
    const normalizedDestDir = normalizeRelativePath(destinationDirInput);
    const target = normalizedDestDir ? `${normalizedDestDir}/${baseName}` : baseName;
    const resolved = normalizeRelativePath(target);
    if (resolved === normalizedSource && conflictPolicy !== 'keep-both') {
        throw new McBrowserRequestError(
            400,
            'SAME_PATH',
            `Destination path "${resolved}" is identical to the source path.`
        );
    }
    if (resolved.startsWith(`${normalizedSource}/`)) {
        throw new McBrowserRequestError(
            400,
            'SUBPATH_CONFLICT',
            `Cannot move or copy "${normalizedSource}" into its own subdirectory "${resolved}".`
        );
    }
    return resolved;
}

export async function downloadMcBrowserArchive(
    paths: string[],
    format: McBrowserArchiveFormat = 'zip',
    options?: {
        signal?: AbortSignal;
        maxBlobBytes?: number;
        saveFilePicker?: SaveFilePickerFn;
    }
): Promise<McBrowserArchiveDownloadResult> {
    if (!Array.isArray(paths) || paths.length === 0) {
        throw new McBrowserRequestError(
            400,
            'EMPTY_SELECTION',
            'Select at least one entry to download as an archive.'
        );
    }

    const normalizedPaths = paths.map((p) => {
        const norm = normalizeRelativePath(p);
        if (!norm) {
            throw new McBrowserRequestError(400, 'INVALID_PATH', 'Archive entries must be valid relative paths.');
        }
        return norm;
    });

    const maxBytes = options?.maxBlobBytes ?? MAX_ARCHIVE_BLOB_FALLBACK_BYTES;
    const defaultFilename = `mcbrowser-archive.${format}`;

    const picker =
        options?.saveFilePicker ??
        (typeof window !== 'undefined' &&
        typeof (window as unknown as { showSaveFilePicker?: SaveFilePickerFn }).showSaveFilePicker === 'function'
            ? (window as unknown as { showSaveFilePicker: SaveFilePickerFn }).showSaveFilePicker.bind(window)
            : undefined);

    if (!picker && options?.maxBlobBytes === undefined) {
        const ticket = await mcbrowserJsonRequest<{ url: string; filename: string }>(
            `${MCBROWSER_BASE}/archive-ticket`,
            { method: 'POST', body: JSON.stringify({ paths: normalizedPaths, format }), signal: options?.signal },
            'Failed to prepare archive download.'
        );
        navigateMcBrowserDownload(ticket.url, ticket.filename);
        return { filename: ticket.filename, bytesWritten: 0, method: 'browser-navigation' };
    }

    let fileHandle: FileSystemFileHandleLike | null = null;
    if (picker) {
        fileHandle = await picker({ suggestedName: defaultFilename });
    }

    const res = await apiFetch(`${MCBROWSER_BASE}/archive`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Cache-Control': 'no-store',
        },
        body: JSON.stringify({
            paths: normalizedPaths,
            format,
        }),
        signal: options?.signal,
    });

    if (!res.ok) {
        throw await parseWorkspaceErrorResponse(res, 'Failed to download archive.');
    }

    const disposition = res.headers.get('Content-Disposition') || '';
    const filename = parseFilenameFromContentDisposition(disposition) || defaultFilename;

    const contentLengthHeader = res.headers.get('Content-Length');
    const declaredLength = contentLengthHeader ? Number.parseInt(contentLengthHeader, 10) : NaN;

    if (fileHandle) {
        if (!res.body || typeof res.body.getReader !== 'function') {
            throw new McBrowserRequestError(
                501,
                'STREAMING_UNSUPPORTED',
                'ReadableStream body is unavailable for File System Access streaming download.'
            );
        }
        const writable = await fileHandle.createWritable();
        const reader = res.body.getReader();
        let bytesWritten = 0;
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value) {
                    bytesWritten += value.byteLength;
                    await writable.write(value);
                }
            }
            await writable.close();
        } catch (err) {
            if (typeof writable.abort === 'function') {
                await writable.abort(err).catch(() => {});
            }
            throw err;
        }
        return {
            filename,
            bytesWritten,
            method: 'filesystem-access',
        };
    }

    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        throw new McBrowserRequestError(
            413,
            'ARCHIVE_TOO_LARGE_FOR_BLOB_FALLBACK',
            `Archive size (${declaredLength} bytes) exceeds the ${Math.round(
                maxBytes / (1024 * 1024)
            )} MiB browser memory cap when File System Access streaming is unavailable.`
        );
    }

    if (!res.body || typeof res.body.getReader !== 'function') {
        throw new McBrowserRequestError(
            501,
            'STREAMING_UNSUPPORTED',
            'Streaming response body is unavailable and unbounded blob buffering is disabled. Use a browser with ReadableStream or File System Access support.'
        );
    }

    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
            totalBytes += value.byteLength;
            if (totalBytes > maxBytes) {
                await reader.cancel('Archive exceeded bounded fallback cap').catch(() => {});
                throw new McBrowserRequestError(
                    413,
                    'ARCHIVE_TOO_LARGE_FOR_BLOB_FALLBACK',
                    `Archive stream exceeded the ${Math.round(
                        maxBytes / (1024 * 1024)
                    )} MiB bounded memory cap. Use a Chromium-based browser with File System Access API for direct disk streaming.`
                );
            }
            chunks.push(value);
        }
    }

    const blob = new Blob(chunks as BlobPart[], {
        type: res.headers.get('Content-Type') || 'application/octet-stream',
    });

    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        const objectUrl = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = objectUrl;
        anchor.download = filename;
        anchor.rel = 'noopener';
        anchor.style.display = 'none';
        document.body.appendChild(anchor);
        try {
            anchor.click();
        } finally {
            document.body.removeChild(anchor);
            setTimeout(() => {
                window.URL.revokeObjectURL(objectUrl);
            }, 250);
        }
    }

    return {
        filename,
        bytesWritten: totalBytes,
        method: 'bounded-blob',
    };
}
