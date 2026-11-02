import { TextEncoder, TextDecoder } from 'util';
import React, { useState } from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import McBrowserCodeEditor from '@/components/mcbrowser/McBrowserCodeEditor';
import { renderSafeMarkdownPreview } from '@/lib/mcbrowser-editor';

jest.mock('@/lib/mcbrowser-editor', () => {
    const actualHelpers = jest.requireActual<typeof import('@/lib/mcbrowser-editor')>('@/lib/mcbrowser-editor');
    return {
        ...actualHelpers,
        renderSafeMarkdownPreview: jest.fn(actualHelpers.renderSafeMarkdownPreview),
    };
});

Object.assign(globalThis, { TextEncoder, TextDecoder });

function ControlledEditorHarness({
    initialPath = 'src/app.ts',
    initialValue = 'const x: number = 1;',
    readOnly = false,
    theme = 'chrome',
    onSave,
    onValueChange,
}: {
    initialPath?: string;
    initialValue?: string;
    readOnly?: boolean;
    theme?: string;
    onSave?: () => void;
    onValueChange?: (val: string) => void;
}) {
    const [path, setPath] = useState(initialPath);
    const [value, setValue] = useState(initialValue);

    return (
        <div>
            <button type="button" onClick={() => setPath('README.md')}>
                Switch to Markdown
            </button>
            <button type="button" onClick={() => setPath('legacy/file.cob')}>
                Switch to Unbundled COBOL
            </button>
            <McBrowserCodeEditor
                path={path}
                value={value}
                onChange={(next) => {
                    setValue(next);
                    onValueChange?.(next);
                }}
                readOnly={readOnly}
                theme={theme}
                onSave={onSave}
            />
        </div>
    );
}

describe('McBrowserCodeEditor component', () => {
    beforeEach(() => {
        jest.restoreAllMocks();
        jest.mocked(renderSafeMarkdownPreview).mockImplementation(
            jest.requireActual<typeof import('@/lib/mcbrowser-editor')>('@/lib/mcbrowser-editor').renderSafeMarkdownPreview
        );
        if (typeof window !== 'undefined' && window.localStorage) {
            window.localStorage.clear();
        }
    });

    it('preserves accessible UTF-8 File Content textbox, applies theme and syntax mode from filename, and disables remote Ace workers/CDN paths', () => {
        const onChange = jest.fn();
        render(
            <McBrowserCodeEditor
                path="configs/server.properties"
                value="motd=AetherFlow"
                onChange={onChange}
                theme="monokai"
            />
        );

        const proxyTextarea = screen.getByLabelText('UTF-8 File Content') as HTMLTextAreaElement;
        expect(proxyTextarea).toBeInTheDocument();
        expect(proxyTextarea.value).toBe('motd=AetherFlow');
        expect(proxyTextarea).toHaveAttribute('data-editor-theme', 'monokai');

        const root = screen.getByTestId('mcbrowser-code-editor');
        expect(root).toHaveAttribute('data-editor-mode', 'ace/mode/properties');
        expect(root).toHaveAttribute('data-editor-mode-name', 'properties');
        expect(root).toHaveAttribute('data-editor-theme', 'monokai');
        expect(root).toHaveAttribute('data-editor-ace-theme', 'ace/theme/monokai');

        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const aceGlobal = require('ace-builds/src-noconflict/ace') as typeof import('ace-builds');
        expect(aceGlobal.config.get('basePath')).toBe('');
        expect(aceGlobal.config.get('workerPath')).toBe('');
        expect(aceGlobal.config.get('loadWorkerFromBlob')).toBe(false);
    });

    it('propagates edits via onChange and switches syntax modes with clean fallback for unbundled extensions', () => {
        const onValueChange = jest.fn();
        render(
            <ControlledEditorHarness
                initialPath="src/index.ts"
                initialValue="export const a = 1;"
                onValueChange={onValueChange}
            />
        );

        const root = screen.getByTestId('mcbrowser-code-editor');
        expect(root).toHaveAttribute('data-editor-mode', 'ace/mode/typescript');

        const proxyTextarea = screen.getByLabelText('UTF-8 File Content') as HTMLTextAreaElement;
        fireEvent.change(proxyTextarea, { target: { value: 'export const a = 2;' } });
        expect(onValueChange).toHaveBeenCalledWith('export const a = 2;');
        expect(proxyTextarea.value).toBe('export const a = 2;');

        fireEvent.click(screen.getByRole('button', { name: 'Switch to Unbundled COBOL' }));
        expect(root).toHaveAttribute('data-editor-mode', 'ace/mode/text');
        expect(root).toHaveAttribute('data-editor-mode-fallback', 'true');
        expect(screen.getByTestId('mcbrowser-editor-mode-badge')).toHaveTextContent(
            /text\(text fallback\)/i
        );
    });

    it('enforces readOnly mode on textbox, Ace surface, and mutating toolbar commands while keeping Find and Command Palette available', () => {
        const onChange = jest.fn();
        const onSave = jest.fn();

        render(
            <McBrowserCodeEditor
                path="src/readonly.rs"
                value="fn main() {}"
                onChange={onChange}
                readOnly={true}
                onSave={onSave}
            />
        );

        expect(screen.getByTestId('mcbrowser-editor-readonly-badge')).toHaveTextContent(
            /Read-only/i
        );

        const proxyTextarea = screen.getByLabelText('UTF-8 File Content') as HTMLTextAreaElement;
        expect(proxyTextarea).toBeDisabled();
        expect(proxyTextarea).toHaveAttribute('readonly');

        fireEvent.change(proxyTextarea, { target: { value: 'mutated' } });
        expect(onChange).not.toHaveBeenCalled();

        expect(screen.getByRole('button', { name: 'Undo' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Redo' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Replace in file' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Cut selection' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Paste from clipboard' })).toBeDisabled();
        expect(screen.queryByRole('button', { name: 'Trigger editor save' })).not.toBeInTheDocument();

        expect(screen.getByRole('button', { name: 'Find in file' })).toBeEnabled();
        expect(screen.getByRole('button', { name: 'Open command palette' })).toBeEnabled();

        fireEvent.keyDown(screen.getByTestId('mcbrowser-code-editor'), {
            key: 's',
            ctrlKey: true,
        });
        expect(onSave).not.toHaveBeenCalled();
    });

    it('bounds font size between 8px and 40px and persists changes to localStorage', () => {
        window.localStorage.setItem('editorFontSize', '9');
        const { unmount } = render(
            <McBrowserCodeEditor
                path="notes.txt"
                value="hello"
                onChange={jest.fn()}
            />
        );

        const decBtn = screen.getByRole('button', { name: 'Decrease font size' });
        const badge = screen.getByTestId('mcbrowser-editor-font-size');

        expect(badge).toHaveTextContent('9px');
        fireEvent.click(decBtn);
        expect(badge).toHaveTextContent('8px');
        expect(window.localStorage.getItem('editorFontSize')).toBe('8');
        expect(decBtn).toBeDisabled();

        unmount();

        window.localStorage.setItem('editorFontSize', '39');
        render(
            <McBrowserCodeEditor
                path="notes.txt"
                value="hello"
                onChange={jest.fn()}
            />
        );

        const incBtnMax = screen.getByRole('button', { name: 'Increase font size' });
        const badgeMax = screen.getByTestId('mcbrowser-editor-font-size');
        expect(badgeMax).toHaveTextContent('39px');
        fireEvent.click(incBtnMax);
        expect(badgeMax).toHaveTextContent('40px');
        expect(window.localStorage.getItem('editorFontSize')).toBe('40');
        expect(incBtnMax).toBeDisabled();
    });

    it('shows Markdown preview toggle only for .md/.markdown files, renders KaTeX MathML, and sanitizes XSS/remote images', async () => {
        const markdownWithMathAndXss = [
            '# Release Notes',
            'Inline math $a^2 + b^2 = c^2$ and display:',
            '$$\n\\sum_{i=1}^n i\n$$',
            '<script>window.evilPreview = true;</script>',
            '<img src="https://evil.example/tracker.png" onerror="alert(1)" />',
            '[Malicious Link](javascript:alert(1))',
        ].join('\n\n');

        const { rerender } = render(
            <McBrowserCodeEditor
                path="src/script.js"
                value="console.log(1);"
                onChange={jest.fn()}
            />
        );

        expect(
            screen.queryByRole('button', { name: 'Toggle Markdown preview' })
        ).not.toBeInTheDocument();

        rerender(
            <McBrowserCodeEditor
                path="docs/CHANGELOG.md"
                value={markdownWithMathAndXss}
                onChange={jest.fn()}
            />
        );

        const previewBtn = screen.getByRole('button', { name: 'Toggle Markdown preview' });
        expect(previewBtn).toBeInTheDocument();
        expect(previewBtn).toHaveAttribute('aria-pressed', 'false');

        fireEvent.click(previewBtn);
        expect(previewBtn).toHaveAttribute('aria-pressed', 'true');

        const previewContent = await screen.findByTestId('mcbrowser-markdown-preview-content');
        expect(previewContent.innerHTML).toContain('<h1>Release Notes</h1>');
        expect(previewContent.querySelector('math')).not.toBeNull();
        expect(previewContent.querySelector('script')).toBeNull();
        expect(previewContent.querySelector('img')).toBeNull();
        const link = previewContent.querySelector('a');
        expect(link?.getAttribute('href')).toBeNull();
    });

    it('displays accessible preview error alert when Markdown rendering fails', () => {
        jest.mocked(renderSafeMarkdownPreview).mockImplementation(() => ({
            html: '',
            error: 'KaTeX / Markdown syntax pipeline error',
        }));

        render(
            <McBrowserCodeEditor
                path="docs/broken.markdown"
                value="# Broken"
                onChange={jest.fn()}
            />
        );

        fireEvent.click(screen.getByRole('button', { name: 'Toggle Markdown preview' }));

        const alert = screen.getByTestId('mcbrowser-markdown-preview-error');
        expect(alert).toBeInTheDocument();
        expect(alert).toHaveTextContent(/Markdown preview failed to render/i);
        expect(alert).toHaveTextContent(/KaTeX \/ Markdown syntax pipeline error/i);
    });

    it('executes Find, Replace, Command Palette, Paste, and Ctrl+S save actions', async () => {
        const onChange = jest.fn();
        const onSave = jest.fn();
        const readText = jest.fn().mockResolvedValue('pasted_token');
        Object.defineProperty(window.navigator, 'clipboard', {
            value: {
                writeText: jest.fn().mockResolvedValue(undefined),
                readText,
            },
            configurable: true,
        });

        render(
            <McBrowserCodeEditor
                path="src/main.ts"
                value="const initial = true;"
                onChange={onChange}
                onSave={onSave}
            />
        );

        fireEvent.click(screen.getByRole('button', { name: 'Find in file' }));
        fireEvent.click(screen.getByRole('button', { name: 'Replace in file' }));
        fireEvent.click(screen.getByRole('button', { name: 'Open command palette' }));
        fireEvent.click(screen.getByRole('button', { name: 'Paste from clipboard' }));

        await waitFor(() => {
            expect(readText).toHaveBeenCalledTimes(1);
        });
        expect(onChange).toHaveBeenCalledWith(expect.stringContaining('pasted_token'));

        fireEvent.keyDown(screen.getByTestId('mcbrowser-code-editor'), {
            key: 's',
            ctrlKey: true,
        });
        expect(onSave).toHaveBeenCalledTimes(1);
    });
});
