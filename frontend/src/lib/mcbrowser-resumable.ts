import { apiFetch } from '@/lib/fetcher';
import {
    MCBROWSER_BASE,
    McBrowserRequestError,
    normalizeRelativePath,
} from '@/lib/mcbrowser';

export const TUS_RESUMABLE_VERSION = '1.0.0';
export const MCBROWSER_UPLOADS_ENDPOINT = `${MCBROWSER_BASE}/uploads`;
export const DEFAULT_TUS_CHUNK_BYTES = 4 * 1024 * 1024;
export const MAX_TUS_CHUNK_BYTES = 4 * 1024 * 1024;
export const FINGERPRINT_SAMPLE_BYTES = 64 * 1024;
export const MAX_RESUMABLE_RETRIES = 3;
export const INITIAL_RETRY_BACKOFF_MS = 200;

export type McBrowserUploadConflictPolicy = 'error' | 'skip' | 'keep-both' | 'overwrite' | 'resume';

export type McBrowserUploadSessionStatus =
    | 'uploading'
    | 'completed'
    | 'in_progress'
    | 'pending'
    | string;

export interface McBrowserResumableProgress {
    uploadedBytes: number;
    totalBytes: number;
    speedBytesPerSecond: number;
}

export interface McBrowserResumableOptions {
    signal?: AbortSignal;
    onProgress?: (progress: McBrowserResumableProgress) => void;
    conflict?: McBrowserUploadConflictPolicy;
    chunkSize?: number;
    retryDelayMs?: number;
}

export interface McBrowserResumableResult {
    success: true;
    path: string;
    skipped?: boolean;
}

export interface McBrowserUploadSessionSummary {
    id: string;
    path: string;
    length: number;
    offset: number;
    status: McBrowserUploadSessionStatus;
    fingerprint?: string;
}

export interface McBrowserUploadSessionHead {
    id: string;
    location: string;
    offset: number;
    length: number;
    status: McBrowserUploadSessionStatus;
    path?: string;
    fingerprint?: string;
    publishedPath?: string;
    conflictPolicy?: McBrowserUploadConflictPolicy;
    skipped?: boolean;
}

export class McBrowserUploadUncertaintyError extends McBrowserRequestError {
    public readonly isUncertainCommit = true;

    constructor(
        message = 'Upload state could not be verified after transport interruption; destination commit is uncertain.',
        details?: unknown
    ) {
        super(0, 'UPLOAD_UNCERTAIN_COMMIT', message, details);
        this.name = 'McBrowserUploadUncertaintyError';
    }
}

export function isMcBrowserUploadUncertainError(err: unknown): boolean {
    if (err instanceof McBrowserUploadUncertaintyError) {
        return true;
    }
    if (err instanceof McBrowserRequestError) {
        return err.code === 'UPLOAD_UNCERTAIN_COMMIT';
    }
    return false;
}

function getCurrentOrigin(): string {
    if (typeof window !== 'undefined' && window.location && window.location.origin) {
        return window.location.origin;
    }
    return 'http://localhost';
}

function encodeBase64Bytes(bytes: Uint8Array): string {
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    for (let index = 0; index < bytes.length; index += 1) {
        binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary);
}

function decodeBase64ToUtf8(encoded: string): string {
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(encoded, 'base64').toString('utf-8');
    }
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return new TextDecoder().decode(bytes);
}

export function encodeTusMetadataValue(value: string): string {
    const utf8Bytes = new TextEncoder().encode(value);
    return encodeBase64Bytes(utf8Bytes);
}

export function serializeTusMetadata(entries: Record<string, string | undefined>): string {
    const pairs: string[] = [];
    for (const [key, rawValue] of Object.entries(entries)) {
        if (rawValue === undefined || rawValue === '') {
            continue;
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
            throw new McBrowserRequestError(
                400,
                'INVALID_METADATA_KEY',
                `Invalid TUS metadata key: ${key}`
            );
        }
        pairs.push(`${key} ${encodeTusMetadataValue(rawValue)}`);
    }
    return pairs.join(',');
}

export function parseTusMetadata(headerValue: string | null | undefined): Record<string, string> {
    const result: Record<string, string> = {};
    if (!headerValue || !headerValue.trim()) {
        return result;
    }

    const items = headerValue.split(',');
    for (const rawItem of items) {
        const trimmed = rawItem.trim();
        if (!trimmed) {
            continue;
        }
        const parts = trimmed.split(/\s+/);
        const key = parts[0];
        if (!key) {
            continue;
        }
        if (parts.length === 1) {
            result[key] = '';
            continue;
        }
        try {
            result[key] = decodeBase64ToUtf8(parts[1]);
        } catch {
            // Ignore malformed metadata pair
        }
    }
    return result;
}

export function validateTusUploadLocation(rawLocation: string | null | undefined): {
    id: string;
    path: string;
} {
    if (!rawLocation || !rawLocation.trim()) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'Server did not return a valid TUS Location header.'
        );
    }

    const trimmed = rawLocation.trim();
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'TUS Location header uses an unsupported or unsafe URI scheme.'
        );
    }

    if (trimmed.startsWith('//')) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'Protocol-relative TUS Location headers are not permitted.'
        );
    }

    const currentOrigin = getCurrentOrigin();
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(trimmed, currentOrigin);
    } catch {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'TUS Location header is not a valid URL.'
        );
    }

    if (parsedUrl.origin !== currentOrigin) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'Cross-origin TUS Location header rejected to prevent credential exfiltration.'
        );
    }

    if (parsedUrl.username || parsedUrl.password || parsedUrl.search || parsedUrl.hash) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'TUS Location header must not contain query parameters, fragments, or credentials.'
        );
    }

    const rawPathOnly = trimmed.replace(/^https?:\/\/[^/]+/i, '');
    if (
        rawPathOnly.includes('..') ||
        rawPathOnly.includes('//') ||
        rawPathOnly.includes('\\') ||
        /%2f|%5c|%00/i.test(rawPathOnly)
    ) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'TUS Location path contains forbidden traversal or encoded separators.'
        );
    }

    const exactMatch = /^\/api\/v1\/auth\/mcbrowser\/uploads\/([A-Za-z0-9_-]{1,128})$/.exec(
        parsedUrl.pathname
    );
    if (!exactMatch || !exactMatch[1]) {
        throw new McBrowserRequestError(
            502,
            'INVALID_UPLOAD_LOCATION',
            'TUS Location path does not match the exact upload session endpoint.'
        );
    }

    const id = exactMatch[1];
    return {
        id,
        path: `${MCBROWSER_UPLOADS_ENDPOINT}/${id}`,
    };
}

function getSubtleCrypto(): SubtleCrypto {
    const cryptoObj =
        typeof globalThis !== 'undefined'
            ? (globalThis as unknown as { crypto?: Crypto }).crypto
            : undefined;
    if (!cryptoObj || !cryptoObj.subtle || typeof cryptoObj.subtle.digest !== 'function') {
        throw new McBrowserRequestError(
            500,
            'CRYPTO_UNAVAILABLE',
            'Web Crypto SHA-256 is required for safe resumable upload fingerprinting.'
        );
    }
    return cryptoObj.subtle;
}

async function readBlobBytes(blob: Blob): Promise<Uint8Array> {
    if (typeof blob.arrayBuffer === 'function') {
        const ab = await blob.arrayBuffer();
        return new Uint8Array(ab);
    }
    if (typeof Response !== 'undefined') {
        const ab = await new Response(blob).arrayBuffer();
        return new Uint8Array(ab);
    }
    throw new McBrowserRequestError(
        500,
        'FILE_READ_UNSUPPORTED',
        'Unable to read file slice bytes in this environment.'
    );
}

function bytesToHex(bytes: Uint8Array): string {
    let hex = '';
    for (let index = 0; index < bytes.length; index += 1) {
        hex += bytes[index].toString(16).padStart(2, '0');
    }
    return hex;
}

export async function computeMcBrowserFileFingerprint(file: File): Promise<string> {
    const subtle = getSubtleCrypto();
    const size =
        typeof file.size === 'number' && Number.isFinite(file.size) && file.size >= 0
            ? Math.trunc(file.size)
            : -1;
    if (size < 0) {
        throw new McBrowserRequestError(400, 'INVALID_FILE', 'File size must be a non-negative integer.');
    }

    const lastModified =
        typeof file.lastModified === 'number' && Number.isFinite(file.lastModified)
            ? Math.trunc(file.lastModified)
            : 0;

    const firstEnd = Math.min(size, FINGERPRINT_SAMPLE_BYTES);
    const firstBytes = firstEnd > 0 ? await readBlobBytes(file.slice(0, firstEnd)) : new Uint8Array(0);

    const lastStart = size > FINGERPRINT_SAMPLE_BYTES ? Math.max(firstEnd, size - FINGERPRINT_SAMPLE_BYTES) : firstEnd;
    const lastBytes =
         size > lastStart ? await readBlobBytes(file.slice(lastStart, size)) : new Uint8Array(0);

    const headerBytes = new TextEncoder().encode(`af-tus-fp-v1:${size}:${lastModified}:`);
    const combined = new Uint8Array(headerBytes.length + firstBytes.length + 1 + lastBytes.length);
    combined.set(headerBytes, 0);
    combined.set(firstBytes, headerBytes.length);
    combined[headerBytes.length + firstBytes.length] = 0x3a; // ':'
    combined.set(lastBytes, headerBytes.length + firstBytes.length + 1);

    const digestBuffer = await subtle.digest('SHA-256', combined);
    const digestHex = bytesToHex(new Uint8Array(digestBuffer));
    return `v1:${size}:${lastModified}:${digestHex}`;
}

async function parseTusErrorResponse(
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
        `Upload request failed (${res.status} ${res.statusText || 'Error'})`;

    return new McBrowserRequestError(res.status, code, message, errObj.details);
}

function parseNonNegativeHeaderInt(value: string | null, headerName: string): number {
    if (value === null || value === undefined || value.trim() === '') {
        throw new McBrowserRequestError(
            502,
            'INVALID_TUS_OFFSET',
            `Missing required ${headerName} response header.`
        );
    }
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
        throw new McBrowserRequestError(
            502,
            'INVALID_TUS_OFFSET',
            `Invalid ${headerName} header value: ${trimmed}`
        );
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new McBrowserRequestError(
            502,
            'INVALID_TUS_OFFSET',
            `Out-of-range ${headerName} header value: ${trimmed}`
        );
    }
    return parsed;
}

function resolvePublishedPathFromHeaders(headers: Headers, fallbackPath: string): string {
    const metadata = parseTusMetadata(headers.get('Upload-Metadata'));
    const candidates = [metadata.path, headers.get('Upload-Path'), headers.get('X-Upload-Path'), headers.get('McBrowser-Path')];
    for (const candidate of candidates) {
        if (!candidate) continue;
        try {
            return normalizeRelativePath(candidate);
        } catch {
            continue;
        }
    }

    return fallbackPath;
}

function clampChunkSize(chunkSize?: number): number {
    if (typeof chunkSize !== 'number' || !Number.isFinite(chunkSize) || chunkSize <= 0) {
        return DEFAULT_TUS_CHUNK_BYTES;
    }
    const truncated = Math.trunc(chunkSize);
    return Math.min(Math.max(1, truncated), MAX_TUS_CHUNK_BYTES);
}

function createAbortError(): Error {
    if (typeof DOMException !== 'undefined') {
        return new DOMException('The operation was aborted.', 'AbortError');
    }
    const error = new Error('The operation was aborted.');
    error.name = 'AbortError';
    return error;
}

function throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
        throw createAbortError();
    }
}

export function waitWithAbort(delayMs: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) {
        return Promise.reject(createAbortError());
    }
    const boundedDelay = Math.max(0, Math.trunc(delayMs));
    return new Promise<void>((resolve, reject) => {
        let timerId: ReturnType<typeof setTimeout> | null = null;
        const onAbort = () => {
            if (timerId !== null) {
                clearTimeout(timerId);
                timerId = null;
            }
            signal?.removeEventListener('abort', onAbort);
            reject(createAbortError());
        };

        if (signal) {
            signal.addEventListener('abort', onAbort, { once: true });
        }

        timerId = setTimeout(() => {
            timerId = null;
            if (signal) {
                signal.removeEventListener('abort', onAbort);
            }
            resolve();
        }, boundedDelay);
    });
}

function isRetryableStatus(status: number): boolean {
    return status === 408 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function isTerminalQuotaOrClientError(err: unknown): err is McBrowserRequestError {
    if (!(err instanceof McBrowserRequestError)) {
        return false;
    }
    if (err.status === 507) {
        // Insufficient Storage is a terminal storage limit error
        return true;
    }
    if (err.status >= 400 && err.status < 500 && err.status !== 408 && err.status !== 409 && err.status !== 429) {
        return true;
    }
    return false;
}

export async function listMcBrowserResumableUploads(params?: {
    path?: string;
    length?: number;
    fingerprint?: string;
    signal?: AbortSignal;
}): Promise<McBrowserUploadSessionSummary[]> {
    throwIfAborted(params?.signal);

    const searchParams = new URLSearchParams();
    if (params?.path !== undefined && params.path !== '') {
        const normalizedPath = normalizeRelativePath(params.path);
        searchParams.set('path', normalizedPath);
    }
    if (params?.length !== undefined) {
        if (!Number.isSafeInteger(params.length) || params.length < 0) {
            throw new McBrowserRequestError(400, 'INVALID_LENGTH', 'Upload length must be a non-negative integer.');
        }
        searchParams.set('length', String(params.length));
    }
    if (params?.fingerprint !== undefined && params.fingerprint !== '') {
        searchParams.set('fingerprint', params.fingerprint);
    }

    const queryString = searchParams.toString();
    const url = queryString
        ? `${MCBROWSER_UPLOADS_ENDPOINT}?${queryString}`
        : MCBROWSER_UPLOADS_ENDPOINT;

    const res = await apiFetch(url, {
        method: 'GET',
        headers: {
            'Tus-Resumable': TUS_RESUMABLE_VERSION,
            'Cache-Control': 'no-store',
        },
        signal: params?.signal,
    });

    if (!res.ok) {
        throw await parseTusErrorResponse(res, 'Failed to list resumable upload sessions.');
    }

    let payload: unknown = null;
    try {
        payload = await res.json();
    } catch {
        payload = null;
    }

    const rawUploads =
        payload &&
        typeof payload === 'object' &&
        Array.isArray((payload as { uploads?: unknown }).uploads)
            ? ((payload as { uploads: unknown[] }).uploads)
            : [];

    const sessions: McBrowserUploadSessionSummary[] = [];
    for (const item of rawUploads) {
        if (!item || typeof item !== 'object') {
            continue;
        }
        const candidate = item as {
            id?: unknown;
            path?: unknown;
            length?: unknown;
            offset?: unknown;
            status?: unknown;
            fingerprint?: unknown;
            metadata?: unknown;
        };

        if (typeof candidate.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(candidate.id)) {
            continue;
        }
        if (typeof candidate.path !== 'string') {
            continue;
        }
        let normalizedItemPath: string;
        try {
            normalizedItemPath = normalizeRelativePath(candidate.path);
        } catch {
            continue;
        }
        if (
            typeof candidate.length !== 'number' ||
            !Number.isSafeInteger(candidate.length) ||
            candidate.length < 0
        ) {
            continue;
        }
        if (
            typeof candidate.offset !== 'number' ||
            !Number.isSafeInteger(candidate.offset) ||
            candidate.offset < 0 ||
            candidate.offset > candidate.length
        ) {
            continue;
        }

        const status =
            typeof candidate.status === 'string' && candidate.status.trim()
                ? candidate.status.trim()
                : 'uploading';

        let fingerprint: string | undefined;
        if (typeof candidate.fingerprint === 'string' && candidate.fingerprint.trim()) {
            fingerprint = candidate.fingerprint.trim();
        } else if (
            candidate.metadata &&
            typeof candidate.metadata === 'object' &&
            typeof (candidate.metadata as { fingerprint?: unknown }).fingerprint === 'string'
        ) {
            fingerprint = ((candidate.metadata as { fingerprint: string }).fingerprint).trim();
        }

        sessions.push({
            id: candidate.id,
            path: normalizedItemPath,
            length: candidate.length,
            offset: candidate.offset,
            status,
            ...(fingerprint ? { fingerprint } : {}),
        });
    }

    return sessions;
}

export async function headMcBrowserResumableUpload(
    sessionLocationOrId: string,
    signal?: AbortSignal
): Promise<McBrowserUploadSessionHead> {
    throwIfAborted(signal);

    const validated = sessionLocationOrId.startsWith('/') || /^https?:\/\//i.test(sessionLocationOrId)
        ? validateTusUploadLocation(sessionLocationOrId)
        : validateTusUploadLocation(`${MCBROWSER_UPLOADS_ENDPOINT}/${sessionLocationOrId}`);

    const res = await apiFetch(validated.path, {
        method: 'HEAD',
        headers: {
            'Tus-Resumable': TUS_RESUMABLE_VERSION,
            'Cache-Control': 'no-store',
        },
        signal,
    });

    if (!res.ok) {
        throw await parseTusErrorResponse(res, 'Failed to query resumable upload session state.');
    }

    const offset = parseNonNegativeHeaderInt(res.headers.get('Upload-Offset'), 'Upload-Offset');
    const lengthHeader = res.headers.get('Upload-Length');
    const length =
        lengthHeader !== null && lengthHeader.trim() !== ''
            ? parseNonNegativeHeaderInt(lengthHeader, 'Upload-Length')
            : offset;

    if (offset > length) {
        throw new McBrowserRequestError(
            502,
            'INVALID_TUS_OFFSET',
            `Server reported Upload-Offset (${offset}) exceeding Upload-Length (${length}).`
        );
    }

    const rawStatus = res.headers.get('Upload-Status');
    const status: McBrowserUploadSessionStatus =
        rawStatus && rawStatus.trim()
            ? rawStatus.trim().toLowerCase()
            : offset === length && length > 0
            ? 'uploading'
            : 'uploading';

    const metadata = parseTusMetadata(res.headers.get('Upload-Metadata'));
    const headerFingerprint = res.headers.get('Upload-Fingerprint')?.trim();
    const fingerprint = headerFingerprint || metadata.fingerprint || undefined;

    let metadataPath: string | undefined;
    if (metadata.path) {
        try {
            metadataPath = normalizeRelativePath(metadata.path);
        } catch {
            metadataPath = undefined;
        }
    }

    const publishedPath = resolvePublishedPathFromHeaders(res.headers, '') || undefined;
    const conflictPolicy = metadata.conflict || 'error';
    if (
        conflictPolicy !== 'error' && conflictPolicy !== 'skip' &&
        conflictPolicy !== 'overwrite' && conflictPolicy !== 'resume' &&
        conflictPolicy !== 'keep-both'
    ) {
        throw new McBrowserRequestError(502, 'INVALID_TUS_CONFLICT_POLICY', 'Server reported an unsupported upload conflict policy.');
    }

    return {
        id: validated.id,
        location: validated.path,
        offset,
        length,
        status,
        ...(metadataPath ? { path: metadataPath } : {}),
        ...(fingerprint ? { fingerprint } : {}),
        ...(publishedPath ? { publishedPath } : {}),
        conflictPolicy,
        skipped: res.headers.get('Upload-Skipped') === 'true',
    };
}

export async function findResumableUploadSession(
    targetRelativePath: string,
    file: File,
    options?: {
        fingerprint?: string;
        signal?: AbortSignal;
        conflict?: McBrowserUploadConflictPolicy;
    }
): Promise<McBrowserUploadSessionHead | null> {
    const normalizedPath = normalizeRelativePath(targetRelativePath);
    if (!normalizedPath) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Target upload path is required.');
    }

    const fingerprint = options?.fingerprint ?? (await computeMcBrowserFileFingerprint(file));
    const sessions = await listMcBrowserResumableUploads({
        path: normalizedPath,
        length: file.size,
        fingerprint,
        signal: options?.signal,
    });

    for (const candidate of sessions) {
        if (candidate.path !== normalizedPath || candidate.length !== file.size) {
            continue;
        }
        if (candidate.status.toLowerCase() === 'completed') {
            continue;
        }

        // If listing already returned a fingerprint, it must match strictly
        if (candidate.fingerprint !== undefined && candidate.fingerprint !== fingerprint) {
            continue;
        }

        const sessionLocation = `${MCBROWSER_UPLOADS_ENDPOINT}/${candidate.id}`;
        try {
            const headInfo = await headMcBrowserResumableUpload(sessionLocation, options?.signal);
            if ((headInfo.conflictPolicy ?? 'error') !== (options?.conflict ?? 'error')) {
                continue;
            }
            const verifiedFingerprint = headInfo.fingerprint ?? candidate.fingerprint;
            // Fail-safe: never resume by size/name alone if neither list nor HEAD verified the fingerprint
            if (!verifiedFingerprint || verifiedFingerprint !== fingerprint) {
                continue;
            }
            if (headInfo.path !== undefined && headInfo.path !== normalizedPath) {
                continue;
            }
            if (headInfo.length !== file.size) {
                continue;
            }
            return headInfo;
        } catch (err) {
            if (options?.signal?.aborted) {
                throw err;
            }
            // If a listed session disappeared (404) or failed validation, skip it and check others
            if (err instanceof McBrowserRequestError && err.status === 404) {
                continue;
            }
            throw err;
        }
    }

    return null;
}

interface CreateTusSessionResult {
    id: string;
    location: string;
    offset: number;
    status: McBrowserUploadSessionStatus;
    publishedPath: string;
    skipped: boolean;
}

async function createTusUploadSession(
    normalizedPath: string,
    file: File,
    fingerprint: string,
    conflict?: McBrowserUploadConflictPolicy,
    signal?: AbortSignal
): Promise<CreateTusSessionResult> {
    throwIfAborted(signal);

    const metadata = serializeTusMetadata({
        path: normalizedPath,
        fingerprint,
        ...(conflict ? { conflict } : {}),
    });

    const headers = new Headers({
        'Tus-Resumable': TUS_RESUMABLE_VERSION,
        'Upload-Length': String(file.size),
        'Upload-Metadata': metadata,
        'Cache-Control': 'no-store',
    });
    if (conflict) {
        headers.set('X-Upload-Conflict', conflict);
    }

    const res = await apiFetch(MCBROWSER_UPLOADS_ENDPOINT, {
        method: 'POST',
        headers,
        signal,
    });

    if (!res.ok) {
        throw await parseTusErrorResponse(res, 'Failed to create resumable upload session.');
    }

    const rawStatus = res.headers.get('Upload-Status')?.trim().toLowerCase() ?? '';
    const publishedPath = resolvePublishedPathFromHeaders(res.headers, normalizedPath);

    if (rawStatus === 'skipped' || res.status === 200 || res.status === 204) {
        const locationHeader = res.headers.get('Location');
        if (!locationHeader && (rawStatus === 'skipped' || conflict === 'skip')) {
            return {
                id: '',
                location: '',
                offset: file.size,
                status: 'completed',
                publishedPath,
                skipped: true,
            };
        }
    }

    const validatedLocation = validateTusUploadLocation(res.headers.get('Location'));
    const offsetHeader = res.headers.get('Upload-Offset');
    const offset =
        offsetHeader !== null && offsetHeader.trim() !== ''
            ? parseNonNegativeHeaderInt(offsetHeader, 'Upload-Offset')
            : 0;

    if (offset > file.size) {
        throw new McBrowserRequestError(
            502,
            'INVALID_TUS_OFFSET',
            `Server returned initial Upload-Offset (${offset}) greater than file size (${file.size}).`
        );
    }

    const isCompletedOnCreate =
        rawStatus === 'completed' && offset === file.size;

    return {
        id: validatedLocation.id,
        location: validatedLocation.path,
        offset,
        status: isCompletedOnCreate ? 'completed' : rawStatus || 'uploading',
        publishedPath,
        skipped: rawStatus === 'skipped' || res.headers.get('Upload-Skipped') === 'true',
    };
}

function verifySessionIdentity(session: McBrowserUploadSessionHead, fingerprint: string, length: number): void {
    if (session.fingerprint !== fingerprint || session.length !== length) {
        throw new McBrowserUploadUncertaintyError('Upload session identity changed while reconciling its state.');
    }
}

async function confirmPublishedUpload(
    location: string,
    fingerprint: string,
    length: number,
    fallbackPath: string,
    retryDelayMs: number,
    signal?: AbortSignal
): Promise<McBrowserResumableResult> {
    for (let attempt = 0; attempt <= MAX_RESUMABLE_RETRIES; attempt += 1) {
        throwIfAborted(signal);
        try {
            const state = await headMcBrowserResumableUpload(location, signal);
            verifySessionIdentity(state, fingerprint, length);
            if (state.offset === length && state.status === 'completed') {
                return { success: true, path: state.publishedPath || fallbackPath, ...(state.skipped ? { skipped: true } : {}) };
            }
        } catch (error) {
            if (signal?.aborted) throw error;
            if (isMcBrowserUploadUncertainError(error)) throw error;
        }
        if (attempt < MAX_RESUMABLE_RETRIES) await waitWithAbort(retryDelayMs * 2 ** attempt, signal);
    }
    throw new McBrowserUploadUncertaintyError('All bytes reached staging, but destination publication could not be confirmed.');
}

export async function uploadMcBrowserResumable(
    path: string,
    file: File,
    options?: McBrowserResumableOptions
): Promise<McBrowserResumableResult> {
    const normalizedPath = normalizeRelativePath(path);
    if (!normalizedPath) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Target upload path is required.');
    }

    if (
        !file ||
        typeof file.size !== 'number' ||
        !Number.isSafeInteger(file.size) ||
        file.size < 0
    ) {
        throw new McBrowserRequestError(400, 'INVALID_FILE', 'A valid File with non-negative size is required.');
    }

    const signal = options?.signal;
    throwIfAborted(signal);

    // Fail-closed if Web Crypto SHA-256 is unavailable
    const fingerprint = await computeMcBrowserFileFingerprint(file);
    throwIfAborted(signal);

    const chunkSize = clampChunkSize(options?.chunkSize);
    const baseRetryDelayMs =
        typeof options?.retryDelayMs === 'number' &&
        Number.isFinite(options.retryDelayMs) &&
        options.retryDelayMs >= 0
            ? Math.trunc(options.retryDelayMs)
            : INITIAL_RETRY_BACKOFF_MS;

    const totalBytes = file.size;
    let sessionBaselineOffset = 0;
    let sessionStartTimestamp = Date.now();

    const emitConfirmedProgress = (confirmedOffset: number) => {
        if (!options?.onProgress) {
            return;
        }
        const boundedOffset = Math.min(Math.max(0, confirmedOffset), totalBytes);
        const elapsedSeconds = Math.max(0.001, (Date.now() - sessionStartTimestamp) / 1000);
        const deltaBytes = Math.max(0, boundedOffset - sessionBaselineOffset);
        const speedBytesPerSecond =
            deltaBytes > 0 ? Math.round(deltaBytes / elapsedSeconds) : 0;

        options.onProgress({
            uploadedBytes: boundedOffset,
            totalBytes,
            speedBytesPerSecond,
        });
    };

    // 1. Discover existing unfinished session if file size > 0
    let sessionLocation: string | null = null;
    let currentOffset = 0;
    let publishedPath = normalizedPath;

    if (totalBytes > 0) {
        const existingSession = await findResumableUploadSession(normalizedPath, file, {
            fingerprint,
            signal,
            conflict: options?.conflict,
        });
        throwIfAborted(signal);

        if (existingSession) {
            if (
                existingSession.status === 'completed' &&
                existingSession.offset === totalBytes
            ) {
                emitConfirmedProgress(totalBytes);
                return {
                    success: true,
                    path: existingSession.publishedPath || existingSession.path || normalizedPath,
                };
            }
            sessionLocation = existingSession.location;
            currentOffset = existingSession.offset;
            sessionBaselineOffset = currentOffset;
            sessionStartTimestamp = Date.now();
            if (existingSession.publishedPath) {
                publishedPath = existingSession.publishedPath;
            }
            emitConfirmedProgress(currentOffset);
        }
    }

    // 2. Create a new upload session if none was recovered
    if (!sessionLocation) {
        const created = await createTusUploadSession(
            normalizedPath,
            file,
            fingerprint,
            options?.conflict,
            signal
        );
        throwIfAborted(signal);

        publishedPath = created.publishedPath || normalizedPath;

        if (created.skipped) {
            emitConfirmedProgress(totalBytes);
            return {
                success: true,
                path: publishedPath,
                skipped: true,
            };
        }

        if (created.status === 'completed' && created.offset === totalBytes) {
            emitConfirmedProgress(totalBytes);
            return {
                success: true,
                path: publishedPath,
            };
        }

        sessionLocation = created.location;
        currentOffset = created.offset;
        sessionBaselineOffset = currentOffset;
        sessionStartTimestamp = Date.now();
        emitConfirmedProgress(currentOffset);
    }

    // 3. Stream chunks via PATCH with HEAD reconciliation and bounded exponential backoff
    let consecutiveRetries = 0;

    while (currentOffset < totalBytes) {
        throwIfAborted(signal);

        const chunkEnd = Math.min(currentOffset + chunkSize, totalBytes);
        const chunkBlob = file.slice(currentOffset, chunkEnd);
        const expectedNextOffset = chunkEnd;

        try {
            const patchRes = await apiFetch(sessionLocation, {
                method: 'PATCH',
                headers: {
                    'Tus-Resumable': TUS_RESUMABLE_VERSION,
                    'Content-Type': 'application/offset+octet-stream',
                    'Upload-Offset': String(currentOffset),
                    'Cache-Control': 'no-store',
                },
                body: chunkBlob,
                signal,
            });

            if (patchRes.status === 204 || patchRes.status === 200) {
                const newOffset = parseNonNegativeHeaderInt(
                    patchRes.headers.get('Upload-Offset'),
                    'Upload-Offset'
                );

                if (newOffset !== expectedNextOffset) {
                    throw new McBrowserRequestError(
                        502,
                        'INVALID_TUS_OFFSET',
                        `Server returned invalid Upload-Offset ${newOffset} after chunk [expected ${currentOffset}..${expectedNextOffset}].`
                    );
                }

                if (newOffset === currentOffset && chunkEnd > currentOffset) {
                    throw new McBrowserRequestError(
                        502,
                        'UPLOAD_OFFSET_STALLED',
                        'Server acknowledged PATCH without advancing Upload-Offset.'
                    );
                }

                publishedPath = resolvePublishedPathFromHeaders(patchRes.headers, publishedPath);
                currentOffset = newOffset;
                consecutiveRetries = 0;
                emitConfirmedProgress(currentOffset);

                const patchStatus = patchRes.headers.get('Upload-Status')?.trim().toLowerCase();
                if (patchStatus === 'completed' && currentOffset === totalBytes) {
                    return {
                        success: true,
                        path: publishedPath,
                        ...(patchRes.headers.get('Upload-Skipped') === 'true' ? { skipped: true } : {}),
                    };
                }
                continue;
            }

            const patchError = await parseTusErrorResponse(
                patchRes,
                'Failed to upload chunk.'
            );

            // Fail fast on HTTP 4xx quota/validation/auth errors (except 408 timeout, 409 offset conflict, 429 rate limit)
            if (isTerminalQuotaOrClientError(patchError)) {
                throw patchError;
            }

            if (patchRes.status !== 409 && !isRetryableStatus(patchRes.status)) {
                throw patchError;
            }

            throw patchError;
        } catch (err) {
            if (signal?.aborted) {
                // Note: Abort pauses the upload without deleting the server session so reselection can resume.
                // Re-throw abort error so caller/queue marks the interrupted in-flight upload appropriately.
                throw err;
            }

            if (isTerminalQuotaOrClientError(err)) {
                throw err;
            }

            if (
                err instanceof McBrowserRequestError &&
                (err.code === 'INVALID_UPLOAD_LOCATION' || err.code === 'INVALID_TUS_OFFSET')
            ) {
                throw err;
            }

            consecutiveRetries += 1;
            const retriesExhausted = consecutiveRetries > MAX_RESUMABLE_RETRIES;

            const backoffMs = baseRetryDelayMs * Math.pow(2, consecutiveRetries - 1);
            if (!retriesExhausted && backoffMs > 0) {
                await waitWithAbort(backoffMs, signal);
            }

            // Reconcile server state via HEAD
            let headState: McBrowserUploadSessionHead;
            try {
                headState = await headMcBrowserResumableUpload(sessionLocation, signal);
            } catch (headErr) {
                if (signal?.aborted) {
                    throw headErr;
                }
                if (isTerminalQuotaOrClientError(headErr)) {
                    throw headErr;
                }
                if (consecutiveRetries >= MAX_RESUMABLE_RETRIES) {
                    throw new McBrowserUploadUncertaintyError(
                        'Upload interrupted and server offset could not be reconciled via HEAD; destination commit state is uncertain.',
                        headErr
                    );
                }
                continue;
            }

            verifySessionIdentity(headState, fingerprint, totalBytes);
            if (headState.offset < currentOffset || headState.offset > expectedNextOffset) {
                throw new McBrowserUploadUncertaintyError('Server offset moved outside the acknowledged upload chunk.');
            }
            if (headState.publishedPath) {
                publishedPath = headState.publishedPath;
            }

            if (headState.offset > currentOffset) {
                // Server committed bytes before transport dropped! Reset retry counter and advance.
                currentOffset = headState.offset;
                consecutiveRetries = 0;
                emitConfirmedProgress(currentOffset);
            } else {
                currentOffset = headState.offset;
            }

            if (headState.status === 'completed' && currentOffset === totalBytes) {
                return {
                    success: true,
                    path: publishedPath,
                    ...(headState.skipped ? { skipped: true } : {}),
                };
            }
            if (retriesExhausted) {
                throw new McBrowserUploadUncertaintyError('Upload retry limit reached without confirmed publication.');
            }
        }
    }

    return confirmPublishedUpload(sessionLocation, fingerprint, totalBytes, publishedPath, baseRetryDelayMs, signal);
}

export async function cancelMcBrowserResumableSession(
    sessionLocationOrId: string,
    signal?: AbortSignal
): Promise<{ cancelled: boolean; alreadyCompleted: boolean }> {
    throwIfAborted(signal);

    const validated =
        sessionLocationOrId.startsWith('/') || /^https?:\/\//i.test(sessionLocationOrId)
            ? validateTusUploadLocation(sessionLocationOrId)
            : validateTusUploadLocation(`${MCBROWSER_UPLOADS_ENDPOINT}/${sessionLocationOrId}`);

    const res = await apiFetch(validated.path, {
        method: 'DELETE',
        headers: {
            'Tus-Resumable': TUS_RESUMABLE_VERSION,
            'Cache-Control': 'no-store',
        },
        signal,
    });

    if (res.status === 204 || res.status === 200) {
        return { cancelled: true, alreadyCompleted: false };
    }

    if (res.status === 409) {
        // Session already completed and published on the server; never promise rollback!
        throw await parseTusErrorResponse(
            res,
            'Upload already completed and published; cannot roll back committed file.'
        );
    }

    throw await parseTusErrorResponse(res, 'Failed to cancel resumable upload session.');
}

export async function cancelMcBrowserResumable(
    path: string,
    file: File,
    options?: { signal?: AbortSignal; conflict?: McBrowserUploadConflictPolicy }
): Promise<{ cancelled: boolean; sessionId?: string }> {
    const normalizedPath = normalizeRelativePath(path);
    if (!normalizedPath) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Target upload path is required.');
    }

    const signal = options?.signal;
    throwIfAborted(signal);

    const fingerprint = await computeMcBrowserFileFingerprint(file);
    throwIfAborted(signal);

    const session = await findResumableUploadSession(normalizedPath, file, {
        fingerprint,
        signal,
        conflict: options?.conflict,
    });

    if (!session) {
        return { cancelled: false };
    }

    await cancelMcBrowserResumableSession(session.location, signal);
    return {
        cancelled: true,
        sessionId: session.id,
    };
}
