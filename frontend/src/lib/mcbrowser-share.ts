/**
 * Public Share API client and helpers for McBrowser (`/share?token=...`).
 *
 * SECURITY & SESSION ISOLATION INVARIANTS:
 * 1. NEVER use `apiFetch` from `@/lib/fetcher`. Public share endpoints can return
 *    `401 Unauthorized` (e.g. password required, wrong password, or expired unlock
 *    cookie) which MUST NOT trigger `af:session-expired` or log out an active
 *    AetherFlow dashboard session.
 * 2. Always use plain `fetch` with `credentials: 'include'` so the backend's
 *    scoped `HttpOnly; SameSite=Lax` unlock cookie (`mcbrowser_share_<prefix>`)
 *    is stored and sent automatically.
 * 3. NEVER place `password`, `access_token`, or `share_token` in URL query parameters.
 * 4. Keep share metadata strictly minimal (`name`, `is_directory`, `password_required`,
 *    `allow_download`, `expires_at`) and never expose owner identities or parent paths.
 */

export const PUBLIC_SHARE_API_BASE = '/api/v1/public/mcbrowser/shares';
export const MIN_SHARE_TOKEN_LENGTH = 16;
export const MAX_SHARE_TOKEN_LENGTH = 256;
export const MAX_SHARE_PASSWORD_BYTES = 1024;

export type PublicShareEntryKind = 'file' | 'directory';

export interface PublicShareMetadata {
    name: string;
    is_directory: boolean;
    password_required: boolean;
    allow_download: boolean;
    expires_at: string | null;
}

export interface UnlockShareResponse {
    success: boolean;
    access_token: string;
    expires_in: number;
}

export interface PublicShareEntry {
    name: string;
    path: string;
    kind: PublicShareEntryKind;
    size: number;
    modified: string | null;
}

export interface PublicShareEntriesResponse {
    path: string;
    entries: PublicShareEntry[];
}

export interface ShareBreadcrumbSegment {
    label: string;
    path: string;
}

export class PublicShareError extends Error {
    public readonly status: number;
    public readonly code: string;
    public readonly details?: unknown;

    constructor(status: number, code: string, message: string, details?: unknown) {
        super(message);
        this.name = 'PublicShareError';
        this.status = status;
        this.code = code;
        this.details = details;
    }

    get isUnavailableOrExpired(): boolean {
        return this.status === 404 || this.code === 'NOT_FOUND' || this.code === 'SHARE_EXPIRED';
    }

    get isUnauthorized(): boolean {
        return this.status === 401 || this.code === 'UNAUTHORIZED' || this.code === 'SHARE_PASSWORD_INVALID';
    }

    get isPasswordInvalid(): boolean {
        return this.status === 401 && this.code === 'SHARE_PASSWORD_INVALID';
    }

    get isForbidden(): boolean {
        return this.status === 403 || this.code === 'FORBIDDEN';
    }

    get isRateLimited(): boolean {
        return this.status === 429 || this.code === 'TOO_MANY_REQUESTS';
    }
}

function hasControlChars(value: string): boolean {
    for (let i = 0; i < value.length; i += 1) {
        const code = value.charCodeAt(i);
        if (code <= 0x1f || code === 0x7f) {
            return true;
        }
    }
    return false;
}

/**
 * Validates a raw share token from `/share?token=...` against backend constraints
 * (`16..=256` chars, no control characters or path/query separators).
 */
export function validatePublicShareToken(rawToken: string | null | undefined): string {
    const trimmed = (rawToken ?? '').trim();
    if (
        trimmed.length < MIN_SHARE_TOKEN_LENGTH ||
        trimmed.length > MAX_SHARE_TOKEN_LENGTH ||
        hasControlChars(trimmed) ||
        /[/?#\\]/.test(trimmed)
    ) {
        throw new PublicShareError(
            400,
            'INVALID_SHARE_TOKEN',
            'Invalid or missing share link token.'
        );
    }
    return trimmed;
}

/**
 * Normalizes and validates a relative sub-path within a shared directory.
 * Rejects absolute paths, traversal segments (`.` / `..`), backslashes, NUL bytes,
 * and temporary upload staging prefixes.
 */
export function normalizeShareSubPath(rawPath: string | null | undefined): string {
    if (!rawPath) return '';
    if (rawPath.startsWith('/') || /[\\\0]/.test(rawPath) || hasControlChars(rawPath)) {
        throw new PublicShareError(
            400,
            'INVALID_PATH',
            'Expected a relative path within the shared folder.'
        );
    }

    const parts = rawPath.split('/').filter((segment) => segment.length > 0);
    if (parts.some((part) => part === '.' || part === '..' || part.startsWith('.af-upload-tmp.'))) {
        throw new PublicShareError(
            400,
            'INVALID_PATH',
            'Directory traversal outside the shared scope is not permitted.'
        );
    }

    const normalized = parts.join('/');
    const encoder = new TextEncoder();
    if (
        parts.length > 64 ||
        encoder.encode(normalized).length > 4096 ||
        parts.some((part) => encoder.encode(part).length > 255)
    ) {
        throw new PublicShareError(
            400,
            'INVALID_PATH',
            'Requested path exceeds the maximum supported depth or length.'
        );
    }

    return normalized;
}

/**
 * Guard ensuring secret credentials (`password`, `access_token`, `share_token`)
 * are never placed into URL query parameters.
 */
export function assertNoSecretQueryParams(url: string): void {
    const qIndex = url.indexOf('?');
    if (qIndex === -1) return;
    const rawQuery = url.slice(qIndex + 1);
    for (const pair of rawQuery.split('&')) {
        if (!pair) continue;
        const key = (pair.split('=')[0] ?? '').trim().toLowerCase();
        if (key === 'password' || key === 'access_token' || key === 'share_token') {
            throw new PublicShareError(
                400,
                'BAD_REQUEST',
                'Passing share passwords or unlock tokens in URL query parameters is not permitted.'
            );
        }
    }
}

/**
 * Strips any unexpected fields and returns strictly minimal public share metadata.
 */
export function sanitizePublicShareMetadata(raw: unknown): PublicShareMetadata {
    if (!raw || typeof raw !== 'object') {
        throw new PublicShareError(500, 'INVALID_RESPONSE', 'Received malformed share metadata.');
    }
    const obj = raw as Record<string, unknown>;
    const rawName = typeof obj.name === 'string' ? obj.name.trim() : '';
    if (!rawName || hasControlChars(rawName)) {
        throw new PublicShareError(500, 'INVALID_RESPONSE', 'Share metadata is missing a valid name.');
    }

    const expiresAt =
        typeof obj.expires_at === 'string' && obj.expires_at.trim().length > 0
            ? obj.expires_at.trim()
            : null;

    return {
        name: rawName,
        is_directory: Boolean(obj.is_directory),
        password_required: Boolean(obj.password_required),
        allow_download: obj.allow_download === undefined ? true : Boolean(obj.allow_download),
        expires_at: expiresAt,
    };
}

/**
 * Evaluates whether a share's `expires_at` timestamp has passed.
 * Fails closed (`true`) if `expires_at` is non-null but unparseable.
 */
export function isShareExpiredAt(
    expiresAt: string | null | undefined,
    nowMs: number = Date.now()
): boolean {
    if (!expiresAt) return false;
    const parsed = Date.parse(expiresAt);
    if (Number.isNaN(parsed)) {
        return true;
    }
    return nowMs >= parsed;
}

export function buildShareBreadcrumbs(
    rootName: string,
    relativePath: string
): ShareBreadcrumbSegment[] {
    const normalized = normalizeShareSubPath(relativePath);
    const cleanRoot = rootName.trim() || 'Shared folder';
    const rootSegment: ShareBreadcrumbSegment = { label: cleanRoot, path: '' };
    if (!normalized) {
        return [rootSegment];
    }

    const segments: ShareBreadcrumbSegment[] = [rootSegment];
    let acc = '';
    for (const part of normalized.split('/')) {
        acc = acc ? `${acc}/${part}` : part;
        segments.push({ label: part, path: acc });
    }
    return segments;
}

export function getParentSharePath(relativePath: string): string {
    const normalized = normalizeShareSubPath(relativePath);
    if (!normalized) return '';
    const parts = normalized.split('/');
    parts.pop();
    return parts.join('/');
}

async function parsePublicShareError(
    res: Response,
    fallbackMessage: string
): Promise<PublicShareError> {
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
        `Share request failed (${res.status})`;

    return new PublicShareError(res.status, code, message, errObj.details);
}

export function extractPublicShareErrorMessage(
    err: unknown,
    fallback = 'Unable to process share request.'
): string {
    if (!err) return fallback;
    if (err instanceof PublicShareError) {
        return err.message || fallback;
    }
    if (err instanceof Error && err.message.trim()) {
        return err.message.trim();
    }
    if (typeof err === 'string' && err.trim()) {
        return err.trim();
    }
    return fallback;
}

interface PublicShareRequestOptions extends Omit<RequestInit, 'credentials'> {
    accessToken?: string | null;
    fallbackErrorMessage?: string;
}

async function publicShareJsonRequest<T>(
    url: string,
    options?: PublicShareRequestOptions
): Promise<T> {
    assertNoSecretQueryParams(url);

    const { accessToken, fallbackErrorMessage = 'Share request failed.', ...init } = options ?? {};
    const headers = new Headers(init.headers);
    if (!headers.has('Accept')) {
        headers.set('Accept', 'application/json');
    }
    if (init.body && typeof init.body === 'string' && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    headers.set('Cache-Control', 'no-store');

    if (accessToken && accessToken.trim()) {
        headers.set('X-McBrowser-Share-Token', accessToken.trim());
    }

    const res = await fetch(url, {
        ...init,
        headers,
        credentials: 'include',
    });

    if (!res.ok) {
        throw await parsePublicShareError(res, fallbackErrorMessage);
    }

    try {
        return (await res.json()) as T;
    } catch {
        return {} as T;
    }
}

/**
 * Fetches minimal public metadata for a share token:
 * `GET /api/v1/public/mcbrowser/shares/:token`
 */
export async function fetchPublicShareMetadata(
    token: string,
    signal?: AbortSignal
): Promise<PublicShareMetadata> {
    const validToken = validatePublicShareToken(token);
    const url = `${PUBLIC_SHARE_API_BASE}/${encodeURIComponent(validToken)}`;
    const raw = await publicShareJsonRequest<unknown>(url, {
        method: 'GET',
        signal,
        fallbackErrorMessage: 'Share not found or has expired.',
    });
    return sanitizePublicShareMetadata(raw);
}

/**
 * Unlocks a password-protected share:
 * `POST /api/v1/public/mcbrowser/shares/:token/unlock`
 *
 * The backend sets an `HttpOnly; SameSite=Lax` scoped cookie (`mcbrowser_share_<prefix>`)
 * and also returns `{ success, access_token, expires_in }`.
 */
export async function unlockPublicShare(
    token: string,
    password: string,
    signal?: AbortSignal
): Promise<UnlockShareResponse> {
    const validToken = validatePublicShareToken(token);
    if (!password) {
        throw new PublicShareError(400, 'EMPTY_PASSWORD', 'Please enter the share password.');
    }
    const passwordBytes = new TextEncoder().encode(password);
    if (passwordBytes.length > MAX_SHARE_PASSWORD_BYTES || password.includes('\0')) {
        throw new PublicShareError(
            400,
            'INVALID_PASSWORD',
            'Share password exceeds the maximum allowed length or contains invalid characters.'
        );
    }

    const url = `${PUBLIC_SHARE_API_BASE}/${encodeURIComponent(validToken)}/unlock`;
    const resp = await publicShareJsonRequest<Partial<UnlockShareResponse>>(url, {
        method: 'POST',
        body: JSON.stringify({ password }),
        signal,
        fallbackErrorMessage: 'Failed to unlock share.',
    });

    return {
        success: Boolean(resp.success),
        access_token: typeof resp.access_token === 'string' ? resp.access_token.trim() : '',
        expires_in: typeof resp.expires_in === 'number' && Number.isFinite(resp.expires_in) ? resp.expires_in : 0,
    };
}

function sanitizePublicEntry(raw: unknown): PublicShareEntry | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const kind = obj.kind;
    if (kind !== 'file' && kind !== 'directory') {
        return null;
    }
    const name = typeof obj.name === 'string' ? obj.name.trim() : '';
    const rawPath = typeof obj.path === 'string' ? obj.path : '';
    if (!name || hasControlChars(name) || /[\\/]/.test(name)) {
        return null;
    }

    let normalizedPath: string;
    try {
        normalizedPath = normalizeShareSubPath(rawPath || name);
    } catch {
        return null;
    }
    if (!normalizedPath) {
        return null;
    }

    const size =
        typeof obj.size === 'number' && Number.isFinite(obj.size) && obj.size >= 0
            ? Math.floor(obj.size)
            : 0;
    const modified =
        typeof obj.modified === 'string' && obj.modified.trim().length > 0
            ? obj.modified.trim()
            : null;

    return {
        name,
        path: normalizedPath,
        kind,
        size,
        modified,
    };
}

/**
 * Lists scoped entries for a public share:
 * `GET /api/v1/public/mcbrowser/shares/:token/entries`
 */
export async function listPublicShareEntries(
    token: string,
    relativePath = '',
    options?: { accessToken?: string | null; signal?: AbortSignal }
): Promise<PublicShareEntriesResponse> {
    const validToken = validatePublicShareToken(token);
    const normalizedPath = normalizeShareSubPath(relativePath);
    const query = normalizedPath ? `?path=${encodeURIComponent(normalizedPath)}` : '';
    const url = `${PUBLIC_SHARE_API_BASE}/${encodeURIComponent(validToken)}/entries${query}`;

    const raw = await publicShareJsonRequest<{ path?: unknown; entries?: unknown }>(url, {
        method: 'GET',
        accessToken: options?.accessToken,
        signal: options?.signal,
        fallbackErrorMessage: 'Failed to load shared entries.',
    });

    const responsePath =
        typeof raw.path === 'string' ? normalizeShareSubPath(raw.path) : normalizedPath;
    const rawEntries = Array.isArray(raw.entries) ? raw.entries : [];
    const entries: PublicShareEntry[] = [];
    for (const item of rawEntries) {
        const sanitized = sanitizePublicEntry(item);
        if (sanitized) {
            entries.push(sanitized);
        }
    }

    return {
        path: responsePath,
        entries,
    };
}

/**
 * Builds the scoped download endpoint URL for a public share:
 * `GET /api/v1/public/mcbrowser/shares/:token/download`
 */
export function buildPublicShareDownloadUrl(token: string, relativePath = ''): string {
    const validToken = validatePublicShareToken(token);
    const normalizedPath = normalizeShareSubPath(relativePath);
    const query = normalizedPath ? `?path=${encodeURIComponent(normalizedPath)}` : '';
    const url = `${PUBLIC_SHARE_API_BASE}/${encodeURIComponent(validToken)}/download${query}`;
    assertNoSecretQueryParams(url);
    return url;
}

export function parseShareContentDispositionFilename(disposition: string): string | null {
    if (!disposition) return null;
    const utf8Match = disposition.match(/filename\*=UTF-8''([^;\r\n]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            const decoded = decodeURIComponent(utf8Match[1].trim().replace(/^["']|["']$/g, ''));
            const cleaned = sanitizeDownloadFilename(decoded);
            if (cleaned) return cleaned;
        } catch {
            // Fall through to standard filename parameter
        }
    }
    const quotedMatch = disposition.match(/filename="([^"]+)"/i);
    if (quotedMatch && quotedMatch[1]) {
        const cleaned = sanitizeDownloadFilename(quotedMatch[1]);
        if (cleaned) return cleaned;
    }
    const plainMatch = disposition.match(/filename=([^;\r\n]+)/i);
    if (plainMatch && plainMatch[1]) {
        const cleaned = sanitizeDownloadFilename(plainMatch[1].trim().replace(/^["']|["']$/g, ''));
        if (cleaned) return cleaned;
    }
    return null;
}

export function sanitizeDownloadFilename(rawName: string | null | undefined): string {
    const trimmed = (rawName ?? '').trim();
    if (!trimmed) return 'download';
    const leaf = trimmed.split(/[\\/]/).pop() ?? '';
    const withoutControl = Array.from(leaf)
        .filter((ch) => {
            const code = ch.charCodeAt(0);
            return code > 0x1f && code !== 0x7f;
        })
        .join('')
        .trim();
    if (!withoutControl || withoutControl === '.' || withoutControl === '..') {
        return 'download';
    }
    return withoutControl;
}

/**
 * Preflights with the same scoped cookie used by native browser attachment navigation.
 * File bytes never accumulate in JavaScript memory.
 */
export async function downloadPublicShareFile(
    token: string,
    relativePath = '',
    options?: {
        fallbackFilename?: string;
        accessToken?: string | null;
        signal?: AbortSignal;
    }
): Promise<{ filename: string; size: number }> {
    const url = buildPublicShareDownloadUrl(token, relativePath);
    const headers = new Headers({
        Accept: '*/*',
        'Cache-Control': 'no-store',
    });
    const res = await fetch(url, {
        method: 'HEAD',
        headers,
        credentials: 'include',
        signal: options?.signal,
    });

    if (!res.ok) {
        throw await parsePublicShareError(res, 'Failed to download shared file.');
    }

    const disposition = res.headers.get('Content-Disposition') || '';
    const extracted = parseShareContentDispositionFilename(disposition);
    const leafFallback =
        options?.fallbackFilename ||
        normalizeShareSubPath(relativePath).split('/').pop() ||
        'download';
    const filename = sanitizeDownloadFilename(extracted || leafFallback);

    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        anchor.rel = 'noopener noreferrer';
        anchor.style.display = 'none';
        document.body.appendChild(anchor);
        try {
            anchor.click();
        } finally {
            document.body.removeChild(anchor);
        }
    }

    const contentLength = Number(res.headers.get('Content-Length'));
    return { filename, size: Number.isSafeInteger(contentLength) && contentLength >= 0 ? contentLength : 0 };
}

export function formatShareBytes(bytes: number, decimals = 1): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    if (i === 0) return `${Math.floor(bytes)} B`;
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatShareTimestamp(isoString: string | null | undefined): string {
    if (!isoString) return '—';
    const parsed = Date.parse(isoString);
    if (Number.isNaN(parsed)) return '—';
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
