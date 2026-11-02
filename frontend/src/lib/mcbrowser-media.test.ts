import { TextEncoder, TextDecoder } from 'util';
import { MCBROWSER_BASE, McBrowserEntry, McBrowserRequestError } from '@/lib/mcbrowser';
import {
    EPUB_DEFAULT_FONT_SIZE,
    EPUB_MAX_FONT_SIZE,
    EPUB_MIN_FONT_SIZE,
    MAX_CSV_PREVIEW_BYTES,
    buildMcBrowserMediaUrl,
    buildMcBrowserSubtitleUrl,
    buildMcBrowserThumbnailUrl,
    clampEpubFontSize,
    classifyMcBrowserMediaCategory,
    decodeCsvBuffer,
    discoverClientSubtitleEntries,
    extractSubtitleLabel,
    fetchMcBrowserCsvBuffer,
    fetchMcBrowserEpub,
    fetchMcBrowserMediaMetadata,
    fetchMcBrowserSubtitles,
    isPreviewableMediaEntry,
    isSubtitleDirectoryName,
    isSupportedSubtitlePath,
    isUnsafeInlineExtension,
    parseCsvContent,
    readPersistedEpubFontSize,
    readPersistedEpubProgress,
    sanitizeEpubXhtmlToChapter,
    writePersistedEpubFontSize,
    writePersistedEpubProgress,
} from '@/lib/mcbrowser-media';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

import { apiFetch } from '@/lib/fetcher';
const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

describe('mcbrowser-media library contracts', () => {
    beforeEach(() => {
        mockedApiFetch.mockReset();
        if (typeof window !== 'undefined' && window.localStorage) {
            window.localStorage.clear();
        }
    });

    it('classifies allowlisted media extensions and explicitly blocks unsafe SVG/HTML inline content', () => {
        expect(classifyMcBrowserMediaCategory('photos/holiday.JPG')).toBe('image');
        expect(classifyMcBrowserMediaCategory('photos/anim.webp')).toBe('image');
        expect(classifyMcBrowserMediaCategory('clips/movie.mp4')).toBe('video');
        expect(classifyMcBrowserMediaCategory('music/track.flac')).toBe('audio');
        expect(classifyMcBrowserMediaCategory('docs/manual.pdf')).toBe('pdf');
        expect(classifyMcBrowserMediaCategory('exports/data.csv')).toBe('csv');
        expect(classifyMcBrowserMediaCategory('library/book.epub')).toBe('epub');

        expect(isUnsafeInlineExtension('vector.svg')).toBe(true);
        expect(isUnsafeInlineExtension('page.html')).toBe(true);
        expect(isUnsafeInlineExtension('chapter.xhtml')).toBe(true);
        expect(classifyMcBrowserMediaCategory('vector.svg')).toBe('unsupported');
        expect(classifyMcBrowserMediaCategory('page.html')).toBe('unsupported');

        expect(() => buildMcBrowserMediaUrl('evil.svg')).toThrow(McBrowserRequestError);
        expect(() => buildMcBrowserThumbnailUrl('evil.html', 'thumb')).toThrow(
            McBrowserRequestError
        );
    });

    it('builds normalized URLs for media, 256/1080 thumbnails, and subtitles', () => {
        expect(buildMcBrowserMediaUrl('movies/clip 1.mp4')).toBe(
            `${MCBROWSER_BASE}/media?path=movies%2Fclip%201.mp4`
        );
        expect(buildMcBrowserThumbnailUrl('photos/pic.jpg', 'thumb')).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=photos%2Fpic.jpg&size=thumb`
        );
        expect(buildMcBrowserThumbnailUrl('photos/pic.jpg', 256)).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=photos%2Fpic.jpg&size=thumb`
        );
        expect(buildMcBrowserThumbnailUrl('photos/pic.jpg', 'big')).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=photos%2Fpic.jpg&size=big`
        );
        expect(buildMcBrowserThumbnailUrl('photos/pic.jpg', 1080)).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=photos%2Fpic.jpg&size=big`
        );
        expect(buildMcBrowserSubtitleUrl('movies/sub/movie.en.srt')).toBe(
            `${MCBROWSER_BASE}/subtitle?path=movies%2Fsub%2Fmovie.en.srt`
        );
        expect(
            extractSubtitleLabel(
                `${MCBROWSER_BASE}/subtitle?path=movies%2Fsub%2Fmovie.en.srt`
            )
        ).toBe('movie.en');
    });

    it('discovers subtitle sidecars in same folder and sub/subs/subtitles child directories', () => {
        expect(isSupportedSubtitlePath('movie.vtt')).toBe(true);
        expect(isSupportedSubtitlePath('movie.srt')).toBe(true);
        expect(isSupportedSubtitlePath('movie.ass')).toBe(true);
        expect(isSupportedSubtitlePath('movie.ssa')).toBe(true);
        expect(isSubtitleDirectoryName('sub')).toBe(true);
        expect(isSubtitleDirectoryName('Subs')).toBe(true);
        expect(isSubtitleDirectoryName('SUBTITLES')).toBe(true);

        const entries: McBrowserEntry[] = [
            { name: 'movie.mp4', path: 'cinema/movie.mp4', kind: 'file', size: 1000, modified: null },
            { name: 'movie.en.vtt', path: 'cinema/movie.en.vtt', kind: 'file', size: 120, modified: null },
            { name: 'movie.fr.srt', path: 'cinema/sub/movie.fr.srt', kind: 'file', size: 140, modified: null },
            { name: 'movie.de.ass', path: 'cinema/subs/movie_de/movie.de.ass', kind: 'file', size: 180, modified: null },
            { name: 'other.srt', path: 'cinema/other.srt', kind: 'file', size: 90, modified: null },
        ];

        const tracks = discoverClientSubtitleEntries('cinema/movie.mp4', entries);
        expect(tracks.map((t) => t.path)).toEqual([
            'cinema/movie.en.vtt',
            'cinema/sub/movie.fr.srt',
            'cinema/subs/movie_de/movie.de.ass',
        ]);
        expect(tracks[0].language).toBe('en');
        expect(tracks[1].language).toBe('fr');
        expect(tracks[2].format).toBe('ass');
    });

    it('parses CSV with comma, semicolon, and both delimiters, quoted cells, and 5 MiB size limit', () => {
        const semicolonCsv = 'Name;;Age;Note\r\n"Ada; Lovelace";;36;"First ""programmer"""\r\n\r\nBob;;40;Builder\r\n';
        const parsed = parseCsvContent(semicolonCsv, 'semicolon');
        expect(parsed.headers).toEqual(['Name', 'Column 2', 'Age', 'Note']);
        expect(parsed.rows).toEqual([
            ['Ada; Lovelace', '', '36', 'First "programmer"'],
            ['Bob', '', '40', 'Builder'],
        ]);

        const mixedCsv = 'id,city;country\n1,Paris;France\n2,Berlin;Germany';
        const bothParsed = parseCsvContent(mixedCsv, 'both');
        expect(bothParsed.headers).toEqual(['id', 'city', 'country']);
        expect(bothParsed.rows).toHaveLength(2);

        const oversized = new Uint8Array(MAX_CSV_PREVIEW_BYTES + 1);
        expect(() => decodeCsvBuffer(oversized, 'utf-8')).toThrow(McBrowserRequestError);
    });

    it('sanitizes EPUB XHTML chapters and strips scripts, SVG, styles, and iframes', () => {
        const maliciousXhtml = `
            <html>
                <head><title>Ignored Title</title><script>window.pwned = true;</script></head>
                <body>
                    <h1>Safe Chapter Heading</h1>
                    <svg onload="alert(1)"><text>Vector payload</text></svg>
                    <p onclick="evil()">First paragraph &amp; clean entities.</p>
                    <iframe src="https://evil.example"></iframe>
                    <div>Second block line 1<br/>line 2.</div>
                </body>
            </html>
        `;
        const chapter = sanitizeEpubXhtmlToChapter('c1', 'OEBPS/ch1.xhtml', maliciousXhtml);
        expect(chapter.title).toBe('Safe Chapter Heading');
        expect(chapter.paragraphs).toEqual([
            'Safe Chapter Heading',
            'First paragraph & clean entities.',
            'Second block line 1',
            'line 2.',
        ]);
        expect(chapter.text).not.toContain('pwned');
        expect(chapter.text).not.toContain('Vector payload');
        expect(chapter.text).not.toContain('evil');
    });

    it('persists and clamps EPUB font size (100-150%) and reading progress in localStorage', () => {
        expect(readPersistedEpubFontSize()).toBe(EPUB_DEFAULT_FONT_SIZE);
        expect(clampEpubFontSize(80)).toBe(EPUB_MIN_FONT_SIZE);
        expect(clampEpubFontSize(200)).toBe(EPUB_MAX_FONT_SIZE);

        writePersistedEpubFontSize(140);
        expect(readPersistedEpubFontSize()).toBe(140);

        writePersistedEpubProgress(3, 'books/manual.epub');
        expect(readPersistedEpubProgress('books/manual.epub')).toBe(3);
        expect(readPersistedEpubProgress()).toBe(3);
    });

    it('fetches subtitles, media metadata, CSV buffers, and EPUB books via API endpoints', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                path: 'movie.mp4',
                subtitles: [
                    {
                        path: 'sub/movie.en.srt',
                        name: 'movie.en.srt',
                        label: 'movie.en',
                        language: 'en',
                        format: 'srt',
                        url: `${MCBROWSER_BASE}/subtitle?path=sub%2Fmovie.en.srt`,
                    },
                ],
            }),
        } as unknown as Response);

        const subs = await fetchMcBrowserSubtitles('movie.mp4');
        expect(subs).toHaveLength(1);
        expect(subs[0].path).toBe('sub/movie.en.srt');

        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                path: 'photo.jpg',
                name: 'photo.jpg',
                kind: 'file',
                content_type: 'image/jpeg',
                size: 4096,
                modified: null,
                resolution: { width: 4000, height: 3000 },
                subtitles: [],
            }),
        } as unknown as Response);

        const meta = await fetchMcBrowserMediaMetadata('photo.jpg');
        expect(meta.resolution).toEqual({ width: 4000, height: 3000 });

        const csvBytes = new TextEncoder().encode('col1,col2\nval1,val2').buffer;
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            arrayBuffer: async () => csvBytes,
        } as unknown as Response);

        const buf = await fetchMcBrowserCsvBuffer('table.csv');
        expect(decodeCsvBuffer(buf, 'utf-8')).toBe('col1,col2\nval1,val2');

        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                path: 'book.epub',
                title: 'Sample Book',
                author: 'Author',
                language: 'en',
                description: null,
                chapters: [
                    {
                        id: 'ch1',
                        title: 'Chapter 1',
                        href: 'OEBPS/ch1.xhtml',
                        paragraphs: ['Hello EPUB'],
                        text: 'Hello EPUB',
                    },
                ],
            }),
        } as unknown as Response);

        const book = await fetchMcBrowserEpub('book.epub');
        expect(book.title).toBe('Sample Book');
        expect(book.chapters[0].paragraphs).toEqual(['Hello EPUB']);
        expect(
            isPreviewableMediaEntry({
                name: 'book.epub',
                path: 'book.epub',
                kind: 'file',
            })
        ).toBe(true);
        expect(
            isPreviewableMediaEntry({
                name: 'alias-photo.png',
                path: 'links/alias-photo.png',
                kind: 'symlink',
                target_kind: 'file',
            })
        ).toBe(true);
        expect(
            isPreviewableMediaEntry({
                name: 'alias-dir',
                path: 'links/alias-dir',
                kind: 'symlink',
                target_kind: 'directory',
            })
        ).toBe(false);
    });
});
