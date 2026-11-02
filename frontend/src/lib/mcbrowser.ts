import { apiFetch } from '@/lib/fetcher';

export type McBrowserEntryKind = 'file' | 'directory' | 'symlink' | 'other';

export interface McBrowserEntry {
    name: string;
    path: string;
    kind: McBrowserEntryKind;
    size: number;
    modified: string | null;
    target_kind?: 'file' | 'directory';
}

export function getMcBrowserEntryTargetKind(entry: McBrowserEntry): McBrowserEntryKind {
    return entry.kind === 'symlink' && (entry.target_kind === 'file' || entry.target_kind === 'directory')
        ? entry.target_kind : entry.kind;
}

export interface McBrowserEntriesResponse {
    path: string;
    entries: McBrowserEntry[];
    max_upload_bytes: number;
}

export interface McBrowserSuccessResponse {
    success: boolean;
    accounting_pending?: boolean;
}

export type McBrowserConflictPolicy = 'error' | 'overwrite' | 'keep-both';
export type McBrowserConflictPolicyInput = McBrowserConflictPolicy | 'override' | 'rename';

export interface McBrowserCopyMoveOptions {
    conflict?: McBrowserConflictPolicyInput;
    signal?: AbortSignal;
}

export interface McBrowserCopyMoveResponse extends McBrowserSuccessResponse {
    path?: string;
    from?: string;
    to?: string;
    accounting_pending?: boolean;
}

export function normalizeMcBrowserConflictPolicy(
    conflict?: McBrowserConflictPolicyInput | null
): McBrowserConflictPolicy | undefined {
    if (!conflict) return undefined;
    const clean = conflict.trim().toLowerCase();
    if (clean === 'error') return 'error';
    if (clean === 'overwrite' || clean === 'override' || clean === 'replace') return 'overwrite';
    if (
        clean === 'keep-both' ||
        clean === 'keep_both' ||
        clean === 'keepboth' ||
        clean === 'rename'
    ) {
        return 'keep-both';
    }
    throw new McBrowserRequestError(
        400,
        'INVALID_CONFLICT_POLICY',
        `Unsupported conflict resolution policy "${conflict}". Expected error, overwrite, or keep-both.`
    );
}

export function resolveMcBrowserCopyMoveCallOptions(
    optionsOrConflict?: McBrowserConflictPolicyInput | McBrowserCopyMoveOptions | AbortSignal,
    signal?: AbortSignal
): { conflict?: McBrowserConflictPolicy; signal?: AbortSignal } {
    if (!optionsOrConflict) {
        return { signal };
    }
    if (
        typeof AbortSignal !== 'undefined' &&
        optionsOrConflict instanceof AbortSignal
    ) {
        return { signal: optionsOrConflict };
    }
    if (typeof optionsOrConflict === 'string') {
        return {
            conflict: normalizeMcBrowserConflictPolicy(optionsOrConflict),
            signal,
        };
    }
    if (typeof optionsOrConflict === 'object' && 'aborted' in optionsOrConflict) {
        return { signal: optionsOrConflict as AbortSignal };
    }
    const opts = optionsOrConflict as McBrowserCopyMoveOptions;
    return {
        conflict: normalizeMcBrowserConflictPolicy(opts.conflict),
        signal: signal ?? opts.signal,
    };
}

export interface McBrowserPreviewResponse {
    path: string;
    content: string;
    truncated: boolean;
}

export class McBrowserRequestError extends Error {
    public readonly status: number;
    public readonly code: string;
    public readonly details?: unknown;

    constructor(status: number, code: string, message: string, details?: unknown) {
        super(message);
        this.name = 'McBrowserRequestError';
        this.status = status;
        this.code = code;
        this.details = details;
    }
}

export const MCBROWSER_BASE = '/api/v1/auth/mcbrowser';
export const DEFAULT_MAX_UPLOAD_BYTES = 64 * 1024 * 1024;
export const MAX_PREVIEW_BYTES = 256 * 1024;
export function normalizeRelativePath(rawPath: string | null | undefined): string {
    if (!rawPath) return '';
    if (rawPath.startsWith('/') || /[\\\0]/.test(rawPath)) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Expected a relative path without backslashes or NUL bytes.');
    }
    const parts = rawPath.split('/').filter((segment) => segment.length > 0);
    if (parts.some((part) => part === '.' || part === '..' || part.startsWith('.af-upload-tmp.'))) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Traversal and reserved paths are not permitted.');
    }

    const normalized = parts.join('/');
    const encoder = new TextEncoder();
    if (parts.length > 64 || encoder.encode(normalized).length > 4096 || parts.some((part) => encoder.encode(part).length > 255)) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Path exceeds the supported length or depth.');
    }
    return normalized;
}
export function joinRelativePath(parentPath: string, name: string): string {
    if (validateEntryName(name)) {
        throw new McBrowserRequestError(
            400,
            'INVALID_NAME',
            'Name must be a single valid file or folder name without path separators.'
        );
    }
    const base = normalizeRelativePath(parentPath);
    return normalizeRelativePath(base ? `${base}/${name}` : name);
}
export function validateEntryName(name: string): string | null {
    const trimmed = name.trim();
    if (!trimmed) {
        return 'Name cannot be empty.';
    }
    if (trimmed === '.' || trimmed === '..') {
        return 'Name cannot be "." or "..".';
    }
    if (/[\\/]/.test(trimmed)) {
        return 'Name cannot contain slashes or path separators.';
    }
    if (/[\0]/.test(trimmed)) {
        return 'Name contains invalid control characters.';
    }
    if (new TextEncoder().encode(name).length > 255) {
        return 'Name exceeds 255 UTF-8 bytes.';
    }
    if (name.startsWith('.af-upload-tmp.')) {
        return 'Name uses a reserved upload prefix.';
    }
    return null;
}
export interface BreadcrumbSegment {
    label: string;
    path: string;
}

export function buildBreadcrumbs(relativePath: string): BreadcrumbSegment[] {
    const normalized = normalizeRelativePath(relativePath);
    const root: BreadcrumbSegment = { label: 'My files', path: '' };
    if (!normalized) {
        return [root];
    }

    const parts = normalized.split('/');
    const segments: BreadcrumbSegment[] = [root];
    let acc = '';
    for (const part of parts) {
        acc = acc ? `${acc}/${part}` : part;
        segments.push({ label: part, path: acc });
    }
    return segments;
}

async function parseErrorResponse(res: Response, fallbackMessage: string): Promise<McBrowserRequestError> {
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

export async function mcbrowserJsonRequest<T>(
    url: string,
    init?: RequestInit,
    fallbackMessage = 'McBrowser request failed.'
): Promise<T> {
    const headers = new Headers(init?.headers);
    if (init?.body && typeof init.body === 'string' && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    headers.set('Cache-Control', 'no-store');

    const res = await apiFetch(url, {
        ...init,
        headers,
    });

    if (!res.ok) {
        throw await parseErrorResponse(res, fallbackMessage);
    }

    try {
        return (await res.json()) as T;
    } catch {
        return {} as T;
    }
}

export function extractMcBrowserError(err: unknown, fallback = 'Operation failed.'): string {
    if (!err) return fallback;
    if (err instanceof McBrowserRequestError) {
        return err.code && !err.code.startsWith('HTTP_')
            ? `${err.message} (${err.code})`
            : err.message;
    }
    if (typeof err === 'object') {
        const maybe = err as { code?: unknown; message?: unknown; error?: unknown };
        const msg =
            (typeof maybe.message === 'string' && maybe.message.trim()) ||
            (typeof maybe.error === 'string' && maybe.error.trim());
        const code = typeof maybe.code === 'string' && maybe.code.trim() ? maybe.code.trim() : '';
        if (msg) {
            return code && !code.startsWith('HTTP_') ? `${msg} (${code})` : msg;
        }
    }
    if (typeof err === 'string' && err.trim()) {
        return err.trim();
    }
    return fallback;
}
export async function listMcBrowserEntries(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserEntriesResponse> {
    const normalized = normalizeRelativePath(relativePath);
    const query = `?path=${encodeURIComponent(normalized)}`;
    return mcbrowserJsonRequest<McBrowserEntriesResponse>(
        `${MCBROWSER_BASE}/entries${query}`,
        { method: 'GET', signal },
        'Failed to load directory entries.'
    );
}
export async function createMcBrowserDirectory(relativePath: string): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Directory path cannot be empty.');
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/directory`,
        {
            method: 'POST',
            body: JSON.stringify({ path: normalized }),
        },
        'Failed to create directory.'
    );
}
export async function ensureMcBrowserDirectory(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Directory path cannot be empty.');
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/directory`,
        { method: 'POST', body: JSON.stringify({ path: normalized, parents: true }), signal },
        'Failed to prepare upload directory.'
    );
}
export async function renameMcBrowserEntry(
    fromPath: string,
    toPath: string,
    optionsOrConflict?: McBrowserConflictPolicyInput | McBrowserCopyMoveOptions | AbortSignal,
    signal?: AbortSignal
): Promise<McBrowserCopyMoveResponse> {
    const normalizedFrom = normalizeRelativePath(fromPath);
    const normalizedTo = normalizeRelativePath(toPath);
    if (!normalizedFrom || !normalizedTo) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Source and destination paths are required.');
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
        `${MCBROWSER_BASE}/rename`,
        {
            method: 'POST',
            body: JSON.stringify(payload),
            ...(resolved.signal ? { signal: resolved.signal } : {}),
        },
        'Failed to rename entry.'
    );
}
export async function deleteMcBrowserEntry(relativePath: string): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Cannot delete root directory.');
    }
    return mcbrowserJsonRequest<McBrowserSuccessResponse>(
        `${MCBROWSER_BASE}/entry?path=${encodeURIComponent(normalized)}`,
        {
            method: 'DELETE',
        },
        'Failed to delete entry.'
    );
}
export async function uploadMcBrowserFile(
    targetRelativePath: string,
    file: File | Blob,
    maxUploadBytes: number = DEFAULT_MAX_UPLOAD_BYTES,
    signal?: AbortSignal
): Promise<McBrowserSuccessResponse> {
    const normalized = normalizeRelativePath(targetRelativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Target upload path is required.');
    }
    if (maxUploadBytes > 0 && file.size > maxUploadBytes) {
        throw new McBrowserRequestError(
            413,
            'FILE_TOO_LARGE',
            `File exceeds maximum upload limit of ${formatBytes(maxUploadBytes)}.`
        );
    }

    const headers = new Headers({
        'Content-Type': file.type || 'application/octet-stream',
        'Cache-Control': 'no-store',
    });

    const res = await apiFetch(`${MCBROWSER_BASE}/upload?path=${encodeURIComponent(normalized)}`, {
        method: 'PUT',
        headers,
        body: file,
        signal,
    });

    if (!res.ok) {
        throw await parseErrorResponse(res, 'Failed to upload file.');
    }

    try {
        return (await res.json()) as McBrowserSuccessResponse;
    } catch {
        return { success: true };
    }
}
export async function fetchMcBrowserPreview(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserPreviewResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'File path is required for preview.');
    }
    return mcbrowserJsonRequest<McBrowserPreviewResponse>(
        `${MCBROWSER_BASE}/preview?path=${encodeURIComponent(normalized)}`,
        { method: 'GET', signal },
        'Failed to preview file.'
    );
}
export async function downloadMcBrowserFile(relativePath: string, fallbackFilename?: string): Promise<void> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'File path is required for download.');
    }

    const url = `${MCBROWSER_BASE}/download?path=${encodeURIComponent(normalized)}`;
    const response = await apiFetch(url, { method: 'HEAD', headers: { 'Cache-Control': 'no-store' } });
    if (!response.ok) {
        throw await parseErrorResponse(response, 'Failed to download file.');
    }
    const filename = parseFilenameFromContentDisposition(response.headers.get('Content-Disposition') || '')
        || fallbackFilename || normalized.split('/').pop() || 'download';
    navigateMcBrowserDownload(url, filename);
}

export function navigateMcBrowserDownload(url: string, filename: string): void {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        throw new McBrowserRequestError(501, 'BROWSER_REQUIRED', 'Downloads require a browser.');
    }
    const resolved = new URL(url, window.location.origin);
    if (resolved.origin !== window.location.origin || !resolved.pathname.startsWith(`${MCBROWSER_BASE}/`)
        || resolved.username || resolved.password || resolved.hash) {
        throw new McBrowserRequestError(400, 'INVALID_DOWNLOAD_URL', 'Download URL is outside the file workspace.');
    }
    const anchor = document.createElement('a');
    anchor.href = `${resolved.pathname}${resolved.search}`;
    anchor.download = filename;
    anchor.rel = 'noopener noreferrer';
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    try {
        anchor.click();
    } finally {
        anchor.remove();
    }
}

export function parseFilenameFromContentDisposition(disposition: string): string | null {
    if (!disposition) return null;
    const utf8Match = disposition.match(/filename\*=UTF-8''([^;\r\n]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            return decodeURIComponent(utf8Match[1].trim().replace(/^["']|["']$/g, ''));
        } catch {
        }
    }
    const quotedMatch = disposition.match(/filename="([^"]+)"/i);
    if (quotedMatch && quotedMatch[1]) {
        return quotedMatch[1].trim();
    }
    const plainMatch = disposition.match(/filename=([^;\r\n]+)/i);
    if (plainMatch && plainMatch[1]) {
        return plainMatch[1].trim().replace(/^["']|["']$/g, '');
    }
    return null;
}

export function formatBytes(bytes: number, decimals = 1): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    if (i === 0) return `${bytes} B`;
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatModifiedDate(modified: string | null | undefined): string {
    if (!modified) return '—';
    const parsed = Date.parse(modified);
    if (Number.isNaN(parsed)) return modified;
    try {
        return new Intl.DateTimeFormat(undefined, {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
        }).format(new Date(parsed));
    } catch {
        return new Date(parsed).toISOString();
    }
}
