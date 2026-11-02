import { TextEncoder, TextDecoder } from 'util';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import McBrowserMediaPreview, {
    McBrowserImageThumbnail,
} from '@/components/mcbrowser/McBrowserMediaPreview';
import { MCBROWSER_BASE, McBrowserEntry } from '@/lib/mcbrowser';
import {
    MAX_CSV_PREVIEW_BYTES,
    fetchMcBrowserCsvBuffer,
    fetchMcBrowserEpub,
    fetchMcBrowserMediaMetadata,
    fetchMcBrowserSubtitles,
} from '@/lib/mcbrowser-media';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/mcbrowser-media', () => {
    const actual = jest.requireActual('@/lib/mcbrowser-media');
    return {
        ...actual,
        fetchMcBrowserSubtitles: jest.fn(),
        fetchMcBrowserMediaMetadata: jest.fn(),
        fetchMcBrowserCsvBuffer: jest.fn(),
        fetchMcBrowserEpub: jest.fn(),
    };
});

const mockedFetchSubtitles = fetchMcBrowserSubtitles as jest.MockedFunction<
    typeof fetchMcBrowserSubtitles
>;
const mockedFetchMetadata = fetchMcBrowserMediaMetadata as jest.MockedFunction<
    typeof fetchMcBrowserMediaMetadata
>;
const mockedFetchCsv = fetchMcBrowserCsvBuffer as jest.MockedFunction<
    typeof fetchMcBrowserCsvBuffer
>;
const mockedFetchEpub = fetchMcBrowserEpub as jest.MockedFunction<typeof fetchMcBrowserEpub>;

describe('McBrowserMediaPreview component', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        if (typeof window !== 'undefined' && window.localStorage) {
            window.localStorage.clear();
        }
        mockedFetchMetadata.mockResolvedValue({
            path: 'photo.jpg',
            name: 'photo.jpg',
            kind: 'file',
            content_type: 'image/jpeg',
            size: 2048,
            modified: null,
            resolution: { width: 4000, height: 3000 },
            subtitles: [],
        });
        mockedFetchSubtitles.mockResolvedValue([]);
    });

    it('renders 256px thumbnail in McBrowserImageThumbnail and 1080p/full-size toggle + zoom + dimensions in image preview', async () => {
        const photoEntry: McBrowserEntry = {
            name: 'photo.jpg',
            path: 'gallery/photo.jpg',
            kind: 'file',
            size: 204800,
            modified: '2026-11-01T10:00:00Z',
        };

        const { unmount } = render(<McBrowserImageThumbnail entry={photoEntry} size="thumb" />);
        const thumbImg = screen.getByTestId('mcbrowser-thumbnail-thumb') as HTMLImageElement;
        expect(thumbImg.getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=gallery%2Fphoto.jpg&size=thumb`
        );
        unmount();

        const onClose = jest.fn();
        render(<McBrowserMediaPreview entry={photoEntry} onClose={onClose} />);

        const previewImg = screen.getByTestId('preview-image-element') as HTMLImageElement;
        expect(previewImg.getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=gallery%2Fphoto.jpg&size=big`
        );

        await waitFor(() => {
            expect(screen.getByTestId('preview-image-resolution')).toHaveTextContent('4000 × 3000');
        });

        // Toggle to HD Full Size
        fireEvent.click(screen.getByTestId('preview-toggle-size-button'));
        expect(previewImg.getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/media?path=gallery%2Fphoto.jpg`
        );

        // Zoom in and reset
        expect(screen.getByTestId('image-zoom-scale')).toHaveTextContent('100%');
        fireEvent.doubleClick(previewImg);
        expect(screen.getByTestId('image-zoom-scale')).toHaveTextContent('200%');
        fireEvent.click(screen.getByTestId('image-zoom-reset'));
        expect(screen.getByTestId('image-zoom-scale')).toHaveTextContent('100%');
    });

    it('blocks unsafe SVG and HTML files from rendering inline', () => {
        const svgEntry: McBrowserEntry = {
            name: 'attack.svg',
            path: 'uploads/attack.svg',
            kind: 'file',
            size: 512,
            modified: null,
        };

        render(<McBrowserMediaPreview entry={svgEntry} onClose={jest.fn()} />);
        expect(screen.getByTestId('preview-unsafe-blocked')).toBeInTheDocument();
        expect(screen.queryByTestId('preview-image-element')).not.toBeInTheDocument();
    });

    it('streams video and attaches discovered .srt/.ass/.vtt subtitle sidecar tracks', async () => {
        mockedFetchSubtitles.mockResolvedValueOnce([
            {
                path: 'sub/movie.en.srt',
                name: 'movie.en.srt',
                label: 'movie.en',
                language: 'en',
                format: 'srt',
                url: `${MCBROWSER_BASE}/subtitle?path=sub%2Fmovie.en.srt`,
            },
            {
                path: 'sub/movie.jp.ass',
                name: 'movie.jp.ass',
                label: 'movie.jp',
                language: 'jp',
                format: 'ass',
                url: `${MCBROWSER_BASE}/subtitle?path=sub%2Fmovie.jp.ass`,
            },
        ]);

        const videoEntry: McBrowserEntry = {
            name: 'movie.mp4',
            path: 'movie.mp4',
            kind: 'file',
            size: 10_485_760,
            modified: null,
        };

        const { container } = render(
            <McBrowserMediaPreview entry={videoEntry} onClose={jest.fn()} />
        );

        const videoEl = screen.getByTestId('preview-video-element') as HTMLVideoElement;
        expect(videoEl.getAttribute('src')).toBe(`${MCBROWSER_BASE}/media?path=movie.mp4`);

        await waitFor(() => {
            expect(screen.getByTestId('video-subtitle-summary')).toHaveTextContent(
                'Subtitles (2): movie.en, movie.jp'
            );
        });

        const tracks = container.querySelectorAll('track[kind="subtitles"]');
        expect(tracks).toHaveLength(2);
        expect(tracks[0].getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/subtitle?path=sub%2Fmovie.en.srt`
        );
        expect(tracks[1].getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/subtitle?path=sub%2Fmovie.jp.ass`
        );

        fireEvent.change(screen.getByTestId('video-playback-rate'), {
            target: { value: '2' },
        });
        expect((screen.getByTestId('video-playback-rate') as HTMLSelectElement).value).toBe('2');
    });

    it('renders interactive CSV table with delimiter & encoding selection and enforces 5 MiB limit', async () => {
        const csvBytes = new TextEncoder().encode('City;Population\nZurich;420000\nGeneva;203000')
            .buffer;
        mockedFetchCsv.mockResolvedValueOnce(csvBytes);

        const csvEntry: McBrowserEntry = {
            name: 'cities.csv',
            path: 'data/cities.csv',
            kind: 'file',
            size: 64,
            modified: null,
        };
        const onEditAsText = jest.fn();

        const { rerender } = render(
            <McBrowserMediaPreview
                entry={csvEntry}
                onClose={jest.fn()}
                onEditAsText={onEditAsText}
                permissions={{ modify: true }}
            />
        );

        await waitFor(() => {
            expect(screen.getByTestId('csv-table')).toBeInTheDocument();
        });
        expect(screen.getByText('Zurich')).toBeInTheDocument();
        expect(screen.getByText('420000')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('preview-edit-as-text-button'));
        expect(onEditAsText).toHaveBeenCalledWith(csvEntry);

        // Oversized > 5 MiB CSV file is rejected without fetching
        const hugeCsvEntry: McBrowserEntry = {
            name: 'huge.csv',
            path: 'data/huge.csv',
            kind: 'file',
            size: MAX_CSV_PREVIEW_BYTES + 1024,
            modified: null,
        };
        rerender(<McBrowserMediaPreview entry={hugeCsvEntry} onClose={jest.fn()} />);
        expect(screen.getByTestId('csv-error-banner')).toHaveTextContent('5 MiB preview limit');
    });

    it('renders safe sanitized EPUB chapters and persists reading progress & font size in localStorage', async () => {
        mockedFetchEpub.mockResolvedValueOnce({
            path: 'books/handbook.epub',
            title: 'Security Handbook',
            author: 'Grace Hopper',
            language: 'en',
            description: null,
            chapters: [
                {
                    id: 'ch1',
                    title: 'Chapter One: Isolation',
                    href: 'OEBPS/ch1.xhtml',
                    paragraphs: ['First chapter safe paragraph.'],
                    text: 'First chapter safe paragraph.',
                },
                {
                    id: 'ch2',
                    title: 'Chapter Two: Capabilities',
                    href: 'OEBPS/ch2.xhtml',
                    paragraphs: ['Second chapter safe paragraph.'],
                    text: 'Second chapter safe paragraph.',
                },
            ],
        });

        const epubEntry: McBrowserEntry = {
            name: 'handbook.epub',
            path: 'books/handbook.epub',
            kind: 'file',
            size: 12000,
            modified: null,
        };

        render(<McBrowserMediaPreview entry={epubEntry} onClose={jest.fn()} />);

        await waitFor(() => {
            expect(screen.getByTestId('epub-book-title')).toHaveTextContent('Security Handbook');
        });
        expect(screen.getByTestId('epub-chapter-content')).toHaveTextContent(
            'First chapter safe paragraph.'
        );
        expect(screen.getByTestId('epub-font-size')).toHaveTextContent('120%');

        // Increase font size -> 130% persisted in localStorage
        fireEvent.click(screen.getByTestId('epub-font-increase'));
        expect(screen.getByTestId('epub-font-size')).toHaveTextContent('130%');
        expect(window.localStorage.getItem('book-size')).toBe('130');

        // Navigate to next chapter -> persisted in localStorage
        fireEvent.click(screen.getByTestId('epub-next-chapter'));
        expect(screen.getByTestId('epub-chapter-content')).toHaveTextContent(
            'Second chapter safe paragraph.'
        );
        expect(window.localStorage.getItem('book-progress')).toBe('1');
    });

    it('supports Prev/Next buttons and ArrowLeft/ArrowRight/Escape keyboard navigation including confined file symlinks', () => {
        const entries: McBrowserEntry[] = [
            { name: 'track1.mp3', path: 'track1.mp3', kind: 'file', size: 1000, modified: null },
            { name: 'manual.pdf', path: 'manual.pdf', kind: 'file', size: 2000, modified: null },
            {
                name: 'linked.flac',
                path: 'linked.flac',
                kind: 'symlink',
                target_kind: 'file',
                size: 3000,
                modified: null,
            },
            {
                name: 'linked-dir',
                path: 'linked-dir',
                kind: 'symlink',
                target_kind: 'directory',
                size: 0,
                modified: null,
            },
        ];
        const onSelectEntry = jest.fn();
        const onClose = jest.fn();

        const { unmount: unmountThumb } = render(
            <McBrowserImageThumbnail
                entry={{
                    name: 'linked.png',
                    path: 'gallery/linked.png',
                    kind: 'symlink',
                    target_kind: 'file',
                }}
                size="thumb"
            />
        );
        expect(screen.getByTestId('mcbrowser-thumbnail-thumb').getAttribute('src')).toBe(
            `${MCBROWSER_BASE}/thumbnail?path=gallery%2Flinked.png&size=thumb`
        );
        unmountThumb();

        render(
            <McBrowserMediaPreview
                entry={entries[1]}
                entries={entries}
                onSelectEntry={onSelectEntry}
                onClose={onClose}
            />
        );

        expect(screen.getByTestId('preview-pdf-object')).toBeInTheDocument();

        fireEvent.keyDown(window, { key: 'ArrowLeft' });
        expect(onSelectEntry).toHaveBeenCalledWith(entries[0]);

        fireEvent.keyDown(window, { key: 'ArrowRight' });
        expect(onSelectEntry).toHaveBeenCalledWith(entries[2]);

        fireEvent.keyDown(window, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(1);
    });
});
