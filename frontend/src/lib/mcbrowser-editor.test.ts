import { TextEncoder, TextDecoder } from 'util';
import {
    EDITOR_DEFAULT_FONT_SIZE,
    EDITOR_MAX_FONT_SIZE,
    EDITOR_MIN_FONT_SIZE,
    clampEditorFontSize,
    copyEditorTextToClipboard,
    createIsolatedMarkdownInstance,
    extractEditorFileName,
    isMarkdownEditorPath,
    readEditorTextFromClipboard,
    readPersistedEditorFontSize,
    renderSafeMarkdownPreview,
    resolveMcBrowserEditorMode,
    resolveMcBrowserEditorTheme,
    writePersistedEditorFontSize,
} from '@/lib/mcbrowser-editor';
import { marked as globalMarked } from 'marked';

Object.assign(globalThis, { TextEncoder, TextDecoder });

describe('mcbrowser-editor helper library', () => {
    beforeEach(() => {
        if (typeof window !== 'undefined' && window.localStorage) {
            window.localStorage.clear();
        }
    });

    describe('filename and Markdown path detection', () => {
        it('extracts basenames and detects .md / .markdown files case-insensitively', () => {
            expect(extractEditorFileName('docs/guides/README.md')).toBe('README.md');
            expect(extractEditorFileName('C:\\server\\notes.MARKDOWN')).toBe('notes.MARKDOWN');
            expect(extractEditorFileName('')).toBe('');

            expect(isMarkdownEditorPath('README.md')).toBe(true);
            expect(isMarkdownEditorPath('nested/guide.markdown')).toBe(true);
            expect(isMarkdownEditorPath('nested/GUIDE.MD')).toBe(true);
            expect(isMarkdownEditorPath('server.properties')).toBe(false);
            expect(isMarkdownEditorPath('markdown.txt')).toBe(false);
        });
    });

    describe('Ace mode resolution and local fallback', () => {
        it('resolves common filenames and extensions to locally bundled Ace modes', () => {
            expect(resolveMcBrowserEditorMode('src/index.ts').mode).toBe('ace/mode/typescript');
            expect(resolveMcBrowserEditorMode('src/Component.tsx').mode).toBe('ace/mode/tsx');
            expect(resolveMcBrowserEditorMode('src/app.js').mode).toBe('ace/mode/javascript');
            expect(resolveMcBrowserEditorMode('config/settings.json').mode).toBe('ace/mode/json');
            expect(resolveMcBrowserEditorMode('README.md').mode).toBe('ace/mode/markdown');
            expect(resolveMcBrowserEditorMode('server.properties').mode).toBe(
                'ace/mode/properties'
            );
            expect(resolveMcBrowserEditorMode('docker/Dockerfile').mode).toBe(
                'ace/mode/dockerfile'
            );
            expect(resolveMcBrowserEditorMode('Makefile').mode).toBe('ace/mode/makefile');
            expect(resolveMcBrowserEditorMode('.gitignore').mode).toBe('ace/mode/gitignore');
            expect(resolveMcBrowserEditorMode('.env.production').mode).toBe('ace/mode/ini');
            expect(resolveMcBrowserEditorMode('main.rs').mode).toBe('ace/mode/rust');
            expect(resolveMcBrowserEditorMode('script.py').mode).toBe('ace/mode/python');
            expect(resolveMcBrowserEditorMode('deploy.yaml').mode).toBe('ace/mode/yaml');
            expect(resolveMcBrowserEditorMode('Cargo.toml').mode).toBe('ace/mode/toml');
        });

        it('falls back cleanly to ace/mode/text when modelist returns an unbundled mode or unknown extension', () => {
            const mockModelist = {
                getModeForPath: (p: string) =>
                    p.endsWith('.cob')
                        ? { mode: 'ace/mode/cobol', name: 'cobol' }
                        : { mode: 'ace/mode/text', name: 'text' },
            };

            const cobolRes = resolveMcBrowserEditorMode('legacy/payroll.cob', mockModelist);
            expect(cobolRes.mode).toBe('ace/mode/text');
            expect(cobolRes.name).toBe('text');
            expect(cobolRes.detectedMode).toBe('ace/mode/cobol');
            expect(cobolRes.usedFallback).toBe(true);

            const unknownRes = resolveMcBrowserEditorMode('archive/data.unknownext');
            expect(unknownRes.mode).toBe('ace/mode/text');
            expect(unknownRes.name).toBe('text');
            expect(unknownRes.usedFallback).toBe(false);
        });
    });

    describe('Ace theme resolution', () => {
        it('normalizes bundled theme names and falls back to chrome (light) or twilight (dark)', () => {
            expect(resolveMcBrowserEditorTheme('monokai')).toEqual({
                aceTheme: 'ace/theme/monokai',
                themeKey: 'monokai',
            });
            expect(resolveMcBrowserEditorTheme('ace/theme/dracula')).toEqual({
                aceTheme: 'ace/theme/dracula',
                themeKey: 'dracula',
            });
            expect(resolveMcBrowserEditorTheme('non_existent_theme')).toEqual({
                aceTheme: 'ace/theme/chrome',
                themeKey: 'chrome',
            });
            expect(
                resolveMcBrowserEditorTheme('non_existent_theme', { preferDarkFallback: true })
            ).toEqual({
                aceTheme: 'ace/theme/twilight',
                themeKey: 'twilight',
            });
        });
    });

    describe('Font size clamping and persistence (bounded 8..40)', () => {
        it('clamps font sizes strictly between 8 and 40 with default 14', () => {
            expect(clampEditorFontSize(14)).toBe(14);
            expect(clampEditorFontSize(1)).toBe(EDITOR_MIN_FONT_SIZE);
            expect(clampEditorFontSize(8)).toBe(8);
            expect(clampEditorFontSize(40)).toBe(40);
            expect(clampEditorFontSize(99)).toBe(EDITOR_MAX_FONT_SIZE);
            expect(clampEditorFontSize('invalid')).toBe(EDITOR_DEFAULT_FONT_SIZE);
            expect(clampEditorFontSize(null)).toBe(EDITOR_DEFAULT_FONT_SIZE);
        });

        it('reads and writes clamped font size to storage', () => {
            expect(readPersistedEditorFontSize()).toBe(14);
            expect(writePersistedEditorFontSize(22)).toBe(22);
            expect(readPersistedEditorFontSize()).toBe(22);

            expect(writePersistedEditorFontSize(3)).toBe(8);
            expect(readPersistedEditorFontSize()).toBe(8);

            expect(writePersistedEditorFontSize(100)).toBe(40);
            expect(readPersistedEditorFontSize()).toBe(40);
        });
    });

    describe('Safe Markdown + KaTeX MathML rendering and XSS / network sanitization', () => {
        it('renders Markdown and KaTeX MathML using an isolated Marked instance without mutating global marked', () => {
            const isolated = createIsolatedMarkdownInstance();
            expect(isolated).not.toBe(globalMarked);

            const res = renderSafeMarkdownPreview(
                '# Math Test\n\nInline formula $E = mc^2$ and block:\n\n$$\n\\frac{a}{b}\n$$'
            );
            expect(res.error).toBeNull();
            expect(res.html).toContain('<h1>Math Test</h1>');
            expect(res.html).toContain('<math');
            expect(res.html).toContain('xmlns="http://www.w3.org/1998/Math/MathML"');
            expect(res.html).toContain('<mfrac>');
        });

        it('blocks script tags, event handlers, javascript:/data: URLs, KaTeX trust commands, and remote images/tracking elements', () => {
            const maliciousMarkdown = [
                '# Untrusted Document',
                '<script>window.__xss = 1;</script>',
                '<div onmouseover="alert(1)" onclick="evil()" data-track="secret" style="background:url(https://evil.test/bg)">Text</div>',
                '[Click JS](javascript:alert(document.cookie))',
                '[Click Data](data:text/html,<script>alert(1)</script>)',
                '[Click Control](java\u0000script:alert(1))',
                '[Valid HTTPS](https://example.com/docs)',
                '![Remote Tracker](https://evil.example/pixel.png)',
                '<img src="https://evil.example/track.jpg" srcset="https://evil.example/2x.jpg 2x" onerror="alert(1)" />',
                '<svg onload="alert(1)"><image href="https://evil.example/svg.png" /></svg>',
                '<iframe src="https://evil.example/frame"></iframe>',
                '<audio src="https://evil.example/audio.mp3"></audio>',
                '<video src="https://evil.example/video.mp4" poster="https://evil.example/p.jpg"></video>',
                '<link rel="stylesheet" href="https://evil.example/steal.css" />',
                '$\\href{javascript:alert(1)}{EvilMath}$',
                '$\\url{javascript:alert(1)}$',
                '$\\includegraphics{https://evil.example/math.png}$',
            ].join('\n\n');

            const res = renderSafeMarkdownPreview(maliciousMarkdown);
            expect(res.error).toBeNull();

            const container = document.createElement('div');
            container.innerHTML = res.html;

            expect(container.querySelector('script')).toBeNull();
            expect(container.querySelector('iframe')).toBeNull();
            expect(container.querySelector('img')).toBeNull();
            expect(container.querySelector('svg')).toBeNull();
            expect(container.querySelector('audio')).toBeNull();
            expect(container.querySelector('video')).toBeNull();
            expect(container.querySelector('link')).toBeNull();
            expect(container.querySelector('style')).toBeNull();

            container.querySelectorAll('*').forEach((el) => {
                for (const attr of el.getAttributeNames()) {
                    expect(attr.toLowerCase().startsWith('on')).toBe(false);
                    expect(attr.toLowerCase().startsWith('data-')).toBe(false);
                    expect(['style', 'src', 'srcset', 'xlink:href', 'formaction']).not.toContain(
                        attr.toLowerCase()
                    );
                }
            });

            const anchors = Array.from(container.querySelectorAll('a'));
            for (const a of anchors) {
                const href = a.getAttribute('href');
                if (href) {
                    expect(href).toBe('https://example.com/docs');
                    expect(a.getAttribute('rel')).toBe('noopener noreferrer');
                }
            }
        });

        it('returns structured error UX message when markdown parser throws', () => {
            const failingParser = {
                parse: () => {
                    throw new Error('Synthetic markdown parser failure');
                },
            };

            const res = renderSafeMarkdownPreview('# Broken', { customMarked: failingParser });
            expect(res.html).toBe('');
            expect(res.error).toBe('Synthetic markdown parser failure');
        });
    });

    describe('Clipboard helpers', () => {
        it('copies and reads text using navigator.clipboard when available', async () => {
            const writeText = jest.fn().mockResolvedValue(undefined);
            const readText = jest.fn().mockResolvedValue('pasted-from-clipboard');
            Object.defineProperty(window.navigator, 'clipboard', {
                value: { writeText, readText },
                configurable: true,
            });

            expect(await copyEditorTextToClipboard('copied-value')).toBe(true);
            expect(writeText).toHaveBeenCalledWith('copied-value');

            expect(await readEditorTextFromClipboard()).toBe('pasted-from-clipboard');
            expect(readText).toHaveBeenCalledTimes(1);
        });
    });
});
