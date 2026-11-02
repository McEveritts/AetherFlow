import { apiFetch } from '@/lib/fetcher';
import {
    MCBROWSER_BASE,
    McBrowserEntry,
    McBrowserRequestError,
    mcbrowserJsonRequest,
    normalizeRelativePath,
} from '@/lib/mcbrowser';

export const MAX_CSV_PREVIEW_BYTES = 5 * 1024 * 1024; // 5 MiB
export const MAX_SUBTITLE_BYTES = 2 * 1024 * 1024; // 2 MiB
export const THUMBNAIL_SIZE_THUMB = 256;
export const THUMBNAIL_SIZE_BIG = 1080;
export const MAX_IMAGE_DIMENSION = 10000;

export const EPUB_MIN_FONT_SIZE = 100;
export const EPUB_MAX_FONT_SIZE = 150;
export const EPUB_DEFAULT_FONT_SIZE = 120;
export const EPUB_FONT_STEP = 10;

export const VIDEO_PLAYBACK_RATES = [0.5, 1, 1.5, 2, 2.5, 3] as const;

export type McBrowserMediaCategory =
    | 'image'
    | 'video'
    | 'audio'
    | 'pdf'
    | 'csv'
    | 'epub'
    | 'unsupported';

export type McBrowserThumbnailSize = 'thumb' | 'big' | 256 | 1080;
export type McBrowserCsvSeparatorMode = 'comma' | 'semicolon' | 'both';

export interface McBrowserImageResolution {
    width: number;
    height: number;
}

export interface McBrowserSubtitleTrack {
    path: string;
    name: string;
    label: string;
    language: string | null;
    format: string;
    url: string;
}

export interface McBrowserSubtitlesDiscoveryResponse {
    path: string;
    subtitles: McBrowserSubtitleTrack[];
}

export interface McBrowserMediaMetadataResponse {
    path: string;
    name: string;
    kind: string;
    content_type: string | null;
    size: number;
    modified: string | null;
    resolution: McBrowserImageResolution | null;
    subtitles: McBrowserSubtitleTrack[];
}

export interface McBrowserEpubChapter {
    id: string;
    title: string;
    href: string;
    paragraphs: string[];
    text: string;
}

export interface McBrowserEpubBook {
    path: string;
    title: string;
    author: string | null;
    language: string | null;
    description: string | null;
    chapters: McBrowserEpubChapter[];
}

export interface McBrowserParsedCsv {
    headers: string[];
    rows: string[][];
}

export const AVAILABLE_CSV_ENCODINGS: readonly string[] = [
    'utf-8',
    'windows-1252',
    'iso-8859-1',
    'iso-8859-2',
    'iso-8859-3',
    'iso-8859-4',
    'iso-8859-5',
    'iso-8859-6',
    'iso-8859-7',
    'iso-8859-8',
    'iso-8859-10',
    'iso-8859-13',
    'iso-8859-14',
    'iso-8859-15',
    'iso-8859-16',
    'windows-1250',
    'windows-1251',
    'windows-1253',
    'windows-1254',
    'windows-1255',
    'windows-1256',
    'windows-1257',
    'windows-1258',
    'koi8-r',
    'koi8-u',
    'ibm866',
    'macintosh',
    'gbk',
    'gb18030',
    'big5',
    'shift_jis',
    'euc-jp',
    'iso-2022-jp',
    'euc-kr',
    'utf-16le',
    'utf-16be',
] as const;

const IMAGE_EXTENSIONS = new Set([
    'png',
    'jpg',
    'jpeg',
    'gif',
    'webp',
    'avif',
    'bmp',
    'tif',
    'tiff',
]);

const VIDEO_EXTENSIONS = new Set(['mp4', 'm4v', 'mov', 'webm', 'mkv', 'ogv']);

const AUDIO_EXTENSIONS = new Set([
    'mp3',
    'wav',
    'ogg',
    'oga',
    'opus',
    'flac',
    'm4a',
    'aac',
]);

const SUBTITLE_EXTENSIONS = new Set(['vtt', 'srt', 'ass', 'ssa']);

const UNSAFE_INLINE_EXTENSIONS = new Set([
    'svg',
    'svgz',
    'html',
    'htm',
    'xhtml',
    'xml',
    'mhtml',
]);

export function getFileExtension(pathOrName: string): string {
    const clean = pathOrName.split('?')[0].split('#')[0].trim();
    const leaf = clean.split('/').pop() ?? '';
    const dotIdx = leaf.lastIndexOf('.');
    if (dotIdx <= 0 || dotIdx === leaf.length - 1) {
        return '';
    }
    return leaf.slice(dotIdx + 1).toLowerCase();
}

export function isUnsafeInlineExtension(pathOrName: string): boolean {
    const ext = getFileExtension(pathOrName);
    return UNSAFE_INLINE_EXTENSIONS.has(ext);
}

export function isSupportedSubtitlePath(pathOrName: string): boolean {
    const ext = getFileExtension(pathOrName);
    return SUBTITLE_EXTENSIONS.has(ext);
}

export function isSubtitleDirectoryName(dirName: string): boolean {
    const clean = dirName.trim().toLowerCase();
    return clean === 'sub' || clean === 'subs' || clean === 'subtitles';
}

export function classifyMcBrowserMediaCategory(pathOrName: string): McBrowserMediaCategory {
    if (isUnsafeInlineExtension(pathOrName)) {
        return 'unsupported';
    }
    const ext = getFileExtension(pathOrName);
    if (!ext) {
        return 'unsupported';
    }
    if (IMAGE_EXTENSIONS.has(ext)) {
        return 'image';
    }
    if (VIDEO_EXTENSIONS.has(ext)) {
        return 'video';
    }
    if (AUDIO_EXTENSIONS.has(ext)) {
        return 'audio';
    }
    if (ext === 'pdf') {
        return 'pdf';
    }
    if (ext === 'csv' || ext === 'tsv') {
        return 'csv';
    }
    if (ext === 'epub') {
        return 'epub';
    }
    return 'unsupported';
}

export function isPreviewableMediaEntry(
    entry: Pick<McBrowserEntry, 'kind' | 'target_kind' | 'name' | 'path'>
): boolean {
    const isFileTarget =
        entry.kind === 'file' || (entry.kind === 'symlink' && entry.target_kind === 'file');
    if (!isFileTarget) {
        return false;
    }
    const category = classifyMcBrowserMediaCategory(entry.name || entry.path);
    return category !== 'unsupported';
}

export function buildMcBrowserMediaUrl(relativePath: string): string {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Media file path is required.');
    }
    if (isUnsafeInlineExtension(normalized)) {
        throw new McBrowserRequestError(
            400,
            'UNSAFE_MEDIA_TYPE',
            'HTML and SVG files cannot be rendered as inline media.'
        );
    }
    return `${MCBROWSER_BASE}/media?path=${encodeURIComponent(normalized)}`;
}

export function buildMcBrowserThumbnailUrl(
    relativePath: string,
    size: McBrowserThumbnailSize = 'thumb'
): string {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Image file path is required.');
    }
    if (isUnsafeInlineExtension(normalized)) {
        throw new McBrowserRequestError(
            400,
            'UNSAFE_MEDIA_TYPE',
            'SVG and HTML files are not eligible for image thumbnails.'
        );
    }
    const sizeParam = size === 256 || size === 'thumb' ? 'thumb' : 'big';
    return `${MCBROWSER_BASE}/thumbnail?path=${encodeURIComponent(normalized)}&size=${sizeParam}`;
}

export function buildMcBrowserSubtitleUrl(relativePath: string): string {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Subtitle file path is required.');
    }
    return `${MCBROWSER_BASE}/subtitle?path=${encodeURIComponent(normalized)}`;
}

export function extractSubtitleLabel(subPathOrUrl: string): string {
    let rawLeaf = subPathOrUrl;
    try {
        const parsed = new URL(subPathOrUrl, 'http://localhost');
        const pathParam = parsed.searchParams.get('path');
        if (pathParam) {
            rawLeaf = pathParam;
        } else {
            rawLeaf = decodeURIComponent(parsed.pathname);
        }
    } catch {
        rawLeaf = subPathOrUrl;
    }
    const leaf = rawLeaf.split('/').pop() ?? rawLeaf;
    return leaf.replace(/\.[^/.]+$/, '') || leaf;
}

export function discoverClientSubtitleEntries(
    videoPath: string,
    candidateEntries: McBrowserEntry[]
): McBrowserSubtitleTrack[] {
    const normalizedVideo = normalizeRelativePath(videoPath);
    const videoLeaf = normalizedVideo.split('/').pop() ?? normalizedVideo;
    const dotIdx = videoLeaf.lastIndexOf('.');
    const videoStem = dotIdx > 0 ? videoLeaf.slice(0, dotIdx) : videoLeaf;
    if (!videoStem) {
        return [];
    }
    const parentDir = normalizedVideo.includes('/')
        ? normalizedVideo.slice(0, normalizedVideo.lastIndexOf('/'))
        : '';

    const tracks: McBrowserSubtitleTrack[] = [];
    const seen = new Set<string>();

    for (const entry of candidateEntries) {
        const isFileTarget =
            entry.kind === 'file' || (entry.kind === 'symlink' && entry.target_kind === 'file');
        if (!isFileTarget || !isSupportedSubtitlePath(entry.name)) {
            continue;
        }
        const normalizedSub = normalizeRelativePath(entry.path);
        if (seen.has(normalizedSub)) {
            continue;
        }
        const subParent = normalizedSub.includes('/')
            ? normalizedSub.slice(0, normalizedSub.lastIndexOf('/'))
            : '';
        const parentSegments = subParent ? subParent.split('/') : [];
        const lastDirName = parentSegments[parentSegments.length - 1] ?? '';
        const secondLastDirName = parentSegments[parentSegments.length - 2] ?? '';

        const isSameDir = subParent === parentDir;
        const isDirectSubFolder =
            (parentDir
                ? subParent.toLowerCase().startsWith(`${parentDir.toLowerCase()}/`) &&
                  subParent.split('/').length === parentDir.split('/').length + 1
                : parentSegments.length === 1) && isSubtitleDirectoryName(lastDirName);
        const isNestedSubFolder =
            isSubtitleDirectoryName(secondLastDirName) &&
            lastDirName.toLowerCase().startsWith(videoStem.toLowerCase());

        const matchesStem = entry.name.toLowerCase().startsWith(videoStem.toLowerCase());
        if ((isSameDir && matchesStem) || isDirectSubFolder || isNestedSubFolder) {
            seen.add(normalizedSub);
            const label = extractSubtitleLabel(entry.name);
            const ext = getFileExtension(entry.name);
            let language: string | null = null;
            if (label.toLowerCase().startsWith(videoStem.toLowerCase()) && label.length > videoStem.length) {
                const suffix = label.slice(videoStem.length).replace(/^[._\-\s]+/, '');
                if (suffix && suffix.length <= 16) {
                    language = suffix;
                }
            }
            tracks.push({
                path: normalizedSub,
                name: entry.name,
                label,
                language,
                format: ext,
                url: buildMcBrowserSubtitleUrl(normalizedSub),
            });
        }
    }
    return tracks;
}

export async function fetchMcBrowserSubtitles(
    videoPath: string,
    signal?: AbortSignal
): Promise<McBrowserSubtitleTrack[]> {
    const normalized = normalizeRelativePath(videoPath);
    if (!normalized) {
        return [];
    }
    const resp = await mcbrowserJsonRequest<McBrowserSubtitlesDiscoveryResponse>(
        `${MCBROWSER_BASE}/subtitles?path=${encodeURIComponent(normalized)}`,
        { method: 'GET', signal },
        'Failed to discover video subtitles.'
    );
    return Array.isArray(resp.subtitles) ? resp.subtitles : [];
}

export async function fetchMcBrowserMediaMetadata(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserMediaMetadataResponse> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'Media path is required.');
    }
    return mcbrowserJsonRequest<McBrowserMediaMetadataResponse>(
        `${MCBROWSER_BASE}/media-info?path=${encodeURIComponent(normalized)}`,
        { method: 'GET', signal },
        'Failed to inspect media metadata.'
    );
}

export async function fetchMcBrowserCsvBuffer(
    relativePath: string,
    signal?: AbortSignal
): Promise<ArrayBuffer> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'CSV file path is required.');
    }
    const res = await apiFetch(
        `${MCBROWSER_BASE}/csv?path=${encodeURIComponent(normalized)}`,
        {
            method: 'GET',
            headers: { 'Cache-Control': 'no-store' },
            signal,
        }
    );
    if (!res.ok) {
        let message = `Failed to load CSV preview (${res.status})`;
        let code = `HTTP_${res.status}`;
        try {
            const errJson = (await res.json()) as {
                code?: string;
                message?: string;
                error?: { code?: string; message?: string } | string;
            };
            if (typeof errJson.error === 'object' && errJson.error) {
                code = errJson.error.code || code;
                message = errJson.error.message || message;
            } else {
                code = errJson.code || code;
                message =
                    errJson.message ||
                    (typeof errJson.error === 'string' ? errJson.error : '') ||
                    message;
            }
        } catch {
            // ignore JSON parse error
        }
        throw new McBrowserRequestError(res.status, code, message);
    }
    const buffer = await res.arrayBuffer();
    if (buffer.byteLength > MAX_CSV_PREVIEW_BYTES) {
        throw new McBrowserRequestError(
            413,
            'PAYLOAD_TOO_LARGE',
            'CSV file exceeds the 5 MiB preview limit.'
        );
    }
    return buffer;
}

export function decodeCsvBuffer(
    content: ArrayBuffer | Uint8Array | string,
    encoding = 'utf-8'
): string {
    if (typeof content === 'string') {
        return content;
    }
    const bytes = content instanceof Uint8Array ? content : new Uint8Array(content);
    if (bytes.byteLength > MAX_CSV_PREVIEW_BYTES) {
        throw new McBrowserRequestError(
            413,
            'PAYLOAD_TOO_LARGE',
            'CSV content exceeds the 5 MiB preview limit.'
        );
    }
    const decoder = new TextDecoder(encoding || 'utf-8');
    return decoder.decode(bytes);
}

export function resolveCsvDelimiters(
    mode: McBrowserCsvSeparatorMode | string[] = 'both'
): string[] {
    if (Array.isArray(mode)) {
        return mode.length > 0 ? mode : [',', ';'];
    }
    switch (mode) {
        case 'comma':
            return [','];
        case 'semicolon':
            return [';'];
        case 'both':
        default:
            return [',', ';'];
    }
}

export function parseCsvContent(
    rawText: string,
    separatorMode: McBrowserCsvSeparatorMode | string[] = 'both'
): McBrowserParsedCsv {
    const clean = rawText.replace(/^\uFEFF/, '');
    if (!clean.trim()) {
        return { headers: [], rows: [] };
    }
    const delimiters = new Set(resolveCsvDelimiters(separatorMode));
    const records: string[][] = [];
    let currentRow: string[] = [];
    let currentCell = '';
    let inQuotes = false;

    for (let i = 0; i < clean.length; i++) {
        const ch = clean[i];
        if (inQuotes) {
            if (ch === '"') {
                if (i + 1 < clean.length && clean[i + 1] === '"') {
                    currentCell += '"';
                    i++;
                } else {
                    inQuotes = false;
                }
            } else {
                currentCell += ch;
            }
            continue;
        }

        if (ch === '"' && currentCell.length === 0) {
            inQuotes = true;
            continue;
        }

        if (delimiters.has(ch)) {
            currentRow.push(currentCell);
            currentCell = '';
            continue;
        }

        if (ch === '\r' || ch === '\n') {
            if (ch === '\r' && i + 1 < clean.length && clean[i + 1] === '\n') {
                i++;
            }
            currentRow.push(currentCell);
            currentCell = '';
            const isEmptyRow = currentRow.every((cell) => cell.trim() === '');
            if (!isEmptyRow) {
                records.push(currentRow);
            }
            currentRow = [];
            continue;
        }

        currentCell += ch;
    }

    if (inQuotes) {
        throw new Error('Unterminated quoted field in CSV content.');
    }

    if (currentCell.length > 0 || currentRow.length > 0) {
        currentRow.push(currentCell);
        const isEmptyRow = currentRow.every((cell) => cell.trim() === '');
        if (!isEmptyRow) {
            records.push(currentRow);
        }
    }

    if (records.length === 0) {
        return { headers: [], rows: [] };
    }

    const maxCols = records.reduce((max, r) => Math.max(max, r.length), records[0].length);
    const rawHeaders = records[0];
    const headers: string[] = [];
    for (let col = 0; col < maxCols; col++) {
        const val = (rawHeaders[col] ?? '').trim();
        headers.push(val || `Column ${col + 1}`);
    }

    const rows = records.slice(1).map((row) => {
        const normalizedRow: string[] = [];
        for (let col = 0; col < maxCols; col++) {
            normalizedRow.push(row[col] ?? '');
        }
        return normalizedRow;
    });

    return { headers, rows };
}

function decodeHtmlEntities(input: string): string {
    return input
        .replace(/&nbsp;/gi, ' ')
        .replace(/&#160;/g, ' ')
        .replace(/&#xa0;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&quot;/gi, '"')
        .replace(/&apos;/gi, "'")
        .replace(/&#39;/g, "'");
}

export function sanitizeEpubXhtmlToChapter(
    id: string,
    href: string,
    rawXhtml: string,
    fallbackTitle = 'Chapter'
): McBrowserEpubChapter {
    const withoutDangerous = rawXhtml.replace(
        /<(script|style|svg|iframe|object|embed|applet|form|math|noscript)\b[^>]*>[\s\S]*?<\/\1>/gi,
        ' '
    );
    const headingMatch =
        withoutDangerous.match(/<h1(?:\s[^>]*)?>([\s\S]*?)<\/h1>/i) ||
        withoutDangerous.match(/<h2(?:\s[^>]*)?>([\s\S]*?)<\/h2>/i) ||
        withoutDangerous.match(/<title(?:\s[^>]*)?>([\s\S]*?)<\/title>/i);

    const rawTitle = headingMatch
        ? decodeHtmlEntities(headingMatch[1].replace(/<[^>]+>/g, '')).trim()
        : '';
    const title = rawTitle || fallbackTitle;

    const bodyOnly = withoutDangerous.replace(/<head\b[^>]*>[\s\S]*?<\/head>/gi, ' ');
    const withParagraphBreaks = bodyOnly.replace(
        /<\/(p|div|h1|h2|h3|h4|h5|h6|li|blockquote|section|article|tr)>|<br\s*\/?>/gi,
        '\n\n'
    );
    const stripped = decodeHtmlEntities(withParagraphBreaks.replace(/<[^>]*>/g, ''));
    const paragraphs = stripped
        .split(/\n{2,}/)
        .map((p) => p.replace(/\s+/g, ' ').trim())
        .filter((p) => p.length > 0);

    return {
        id,
        title,
        href,
        paragraphs,
        text: paragraphs.join('\n\n'),
    };
}

export async function fetchMcBrowserEpub(
    relativePath: string,
    signal?: AbortSignal
): Promise<McBrowserEpubBook> {
    const normalized = normalizeRelativePath(relativePath);
    if (!normalized) {
        throw new McBrowserRequestError(400, 'INVALID_PATH', 'EPUB file path is required.');
    }
    const book = await mcbrowserJsonRequest<McBrowserEpubBook>(
        `${MCBROWSER_BASE}/epub?path=${encodeURIComponent(normalized)}`,
        { method: 'GET', signal },
        'Failed to load EPUB book.'
    );
    return {
        ...book,
        chapters: (book.chapters ?? []).map((ch, idx) => ({
            id: ch.id || `ch-${idx + 1}`,
            title: ch.title || `Chapter ${idx + 1}`,
            href: ch.href || '',
            paragraphs: Array.isArray(ch.paragraphs)
                ? ch.paragraphs.map((p) => String(p))
                : String(ch.text || '')
                      .split(/\n{2,}/)
                      .filter(Boolean),
            text: String(ch.text || ''),
        })),
    };
}

export function clampEpubFontSize(size: number): number {
    if (!Number.isFinite(size)) {
        return EPUB_DEFAULT_FONT_SIZE;
    }
    const stepped = Math.round(size / EPUB_FONT_STEP) * EPUB_FONT_STEP;
    return Math.max(EPUB_MIN_FONT_SIZE, Math.min(EPUB_MAX_FONT_SIZE, stepped));
}

export function readPersistedEpubFontSize(): number {
    if (typeof window === 'undefined' || !window.localStorage) {
        return EPUB_DEFAULT_FONT_SIZE;
    }
    try {
        const raw = window.localStorage.getItem('book-size');
        if (!raw) return EPUB_DEFAULT_FONT_SIZE;
        return clampEpubFontSize(JSON.parse(raw) as number);
    } catch {
        return EPUB_DEFAULT_FONT_SIZE;
    }
}

export function writePersistedEpubFontSize(size: number): number {
    const clamped = clampEpubFontSize(size);
    if (typeof window !== 'undefined' && window.localStorage) {
        try {
            window.localStorage.setItem('book-size', JSON.stringify(clamped));
        } catch {
            // ignore storage quota errors
        }
    }
    return clamped;
}

export function readPersistedEpubProgress(bookPath?: string): number {
    if (typeof window === 'undefined' || !window.localStorage) {
        return 0;
    }
    try {
        if (bookPath) {
            const perBook = window.localStorage.getItem(`book-progress:${bookPath}`);
            if (perBook !== null) {
                const parsed = Number(JSON.parse(perBook));
                if (Number.isInteger(parsed) && parsed >= 0) {
                    return parsed;
                }
            }
        }
        const raw = window.localStorage.getItem('book-progress');
        if (!raw) return 0;
        const parsed = Number(JSON.parse(raw));
        return Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
    } catch {
        return 0;
    }
}

export function writePersistedEpubProgress(chapterIndex: number, bookPath?: string): void {
    const clean = Math.max(0, Math.floor(chapterIndex));
    if (typeof window !== 'undefined' && window.localStorage) {
        try {
            window.localStorage.setItem('book-progress', JSON.stringify(clean));
            if (bookPath) {
                window.localStorage.setItem(`book-progress:${bookPath}`, JSON.stringify(clean));
            }
        } catch {
            // ignore storage errors
        }
    }
}
