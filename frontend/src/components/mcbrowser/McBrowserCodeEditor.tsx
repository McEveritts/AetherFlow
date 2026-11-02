'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import type { Ace } from 'ace-builds';
import {
    Undo2,
    Redo2,
    Search,
    Replace,
    Copy,
    Scissors,
    ClipboardPaste,
    Terminal,
    Eye,
    EyeOff,
    Minus,
    Plus,
    Save,
    AlertTriangle,
    Lock,
    FileCode2,
} from 'lucide-react';
import {
    EDITOR_MAX_FONT_SIZE,
    EDITOR_MIN_FONT_SIZE,
    AceModelistLike,
    AceThemelistLike,
    clampEditorFontSize,
    copyEditorTextToClipboard,
    extractEditorFileName,
    isMarkdownEditorPath,
    readEditorTextFromClipboard,
    readPersistedEditorFontSize,
    renderSafeMarkdownPreview,
    resolveMcBrowserEditorMode,
    resolveMcBrowserEditorTheme,
    writePersistedEditorFontSize,
} from '@/lib/mcbrowser-editor';

export interface McBrowserCodeEditorProps {
    path: string;
    value: string;
    onChange: (value: string) => void;
    readOnly?: boolean;
    theme?: string;
    onSave?: () => void;
}

interface LoadedAceRuntime {
    ace: typeof import('ace-builds');
    modelist: AceModelistLike;
    themelist: AceThemelistLike;
}

let cachedAceRuntime: LoadedAceRuntime | null = null;

function ensureLocalAceRuntime(): LoadedAceRuntime | null {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return null;
    }
    if (cachedAceRuntime) {
        return cachedAceRuntime;
    }

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const aceModule = require('ace-builds/src-noconflict/ace') as typeof import('ace-builds');
    const aceGlobal = aceModule;

    const win = window as unknown as Record<string, unknown>;
    const g = globalThis as unknown as Record<string, unknown>;
    if (!win.ace) {
        win.ace = aceGlobal;
    }
    if (!g.ace) {
        g.ace = aceGlobal;
    }

    aceGlobal.config.set('basePath', '');
    aceGlobal.config.set('modePath', '');
    aceGlobal.config.set('themePath', '');
    aceGlobal.config.set('workerPath', '');
    aceGlobal.config.set('loadWorkerFromBlob', false);

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/ext-modelist');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/ext-themelist');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/ext-searchbox');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/ext-prompt');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/ext-language_tools');

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-text');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-javascript');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-typescript');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-tsx');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-jsx');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-json');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-json5');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-markdown');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-html');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-css');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-scss');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-less');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-python');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-rust');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-golang');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-c_cpp');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-java');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-csharp');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-php');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-ruby');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-sh');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-batchfile');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-powershell');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-yaml');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-toml');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-ini');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-properties');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-xml');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-svg');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-sql');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-dockerfile');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-makefile');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-gitignore');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-diff');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-lua');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-perl');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-swift');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-kotlin');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-scala');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-graphqlschema');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-prisma');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-terraform');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-nginx');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-apache_conf');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-latex');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/mode-tex');

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-chrome');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-github');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-solarized_light');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-monokai');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-dracula');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-twilight');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-tomorrow_night');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-solarized_dark');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-textmate');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-clouds');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-dawn');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-eclipse');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-xcode');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-nord_dark');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-one_dark');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-terminal');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ace-builds/src-noconflict/theme-github_dark');

    const modelist = (aceGlobal.require('ace/ext/modelist') || {}) as AceModelistLike;
    const themelist = (aceGlobal.require('ace/ext/themelist') || {}) as AceThemelistLike;

    cachedAceRuntime = {
        ace: aceGlobal,
        modelist,
        themelist,
    };

    return cachedAceRuntime;
}

function getThemeSurfaceClasses(themeKey: string): string {
    if (
        themeKey === 'chrome' ||
        themeKey === 'github' ||
        themeKey === 'solarized_light' ||
        themeKey === 'textmate' ||
        themeKey === 'clouds' ||
        themeKey === 'dawn' ||
        themeKey === 'eclipse' ||
        themeKey === 'xcode'
    ) {
        return 'bg-slate-100 text-slate-900 border-slate-300';
    }
    if (themeKey === 'dracula' || themeKey === 'twilight') {
        return 'bg-indigo-950/90 text-indigo-100 border-indigo-400/30';
    }
    if (themeKey === 'solarized_dark') {
        return 'bg-teal-950/90 text-emerald-100 border-emerald-400/30';
    }
    return 'bg-slate-950/90 text-slate-100 border-white/15';
}

export default function McBrowserCodeEditor({
    path,
    value,
    onChange,
    readOnly = false,
    theme = 'chrome',
    onSave,
}: McBrowserCodeEditorProps) {
    const aceContainerRef = useRef<HTMLDivElement | null>(null);
    const editorInstanceRef = useRef<Ace.Editor | null>(null);
    const isSyncingValueRef = useRef<boolean>(false);
    const onChangeRef = useRef(onChange);
    const onSaveRef = useRef(onSave);
    const readOnlyRef = useRef(readOnly);

    useEffect(() => {
        onChangeRef.current = onChange;
    }, [onChange]);

    useEffect(() => {
        onSaveRef.current = onSave;
    }, [onSave]);

    useEffect(() => {
        readOnlyRef.current = readOnly;
    }, [readOnly]);

    const [fontSize, setFontSize] = useState<number>(() => readPersistedEditorFontSize());
    const [isSelectionEmpty, setIsSelectionEmpty] = useState<boolean>(true);
    const [previewForPath, setPreviewForPath] = useState<string | null>(null);
    const [clipboardNotice, setClipboardNotice] = useState<string | null>(null);

    const fileName = useMemo(() => extractEditorFileName(path), [path]);
    const isMarkdownFile = useMemo(() => isMarkdownEditorPath(path), [path]);
    const isPreviewActive = isMarkdownFile && previewForPath === path;

    const resolvedMode = useMemo(() => {
        const runtime = typeof window !== 'undefined' ? ensureLocalAceRuntime() : null;
        return resolveMcBrowserEditorMode(path, runtime?.modelist);
    }, [path]);

    const resolvedTheme = useMemo(() => {
        const runtime = typeof window !== 'undefined' ? ensureLocalAceRuntime() : null;
        const preferDark =
            typeof document !== 'undefined' &&
            document.documentElement?.classList?.contains('dark');
        return resolveMcBrowserEditorTheme(theme, {
            preferDarkFallback: preferDark,
            themelist: runtime?.themelist,
        });
    }, [theme]);

    const previewResult = useMemo(() => {
        if (!isMarkdownFile || !isPreviewActive) {
            return { html: '', error: null };
        }
        return renderSafeMarkdownPreview(value);
    }, [isMarkdownFile, isPreviewActive, value]);

    useEffect(() => {
        const container = aceContainerRef.current;
        if (!container) return;

        const runtime = ensureLocalAceRuntime();
        if (!runtime) return;

        const initialFontSize = readPersistedEditorFontSize();

        const editor = runtime.ace.edit(container, {
            value,
            showPrintMargin: false,
            readOnly: Boolean(readOnlyRef.current),
            theme: resolvedTheme.aceTheme,
            mode: resolvedMode.mode,
            wrap: true,
            useWorker: false,
            enableBasicAutocompletion: true,
            enableLiveAutocompletion: true,
            enableSnippets: false,
        });

        editor.session.setUseWorker(false);
        editor.setFontSize(initialFontSize);

        const aceTextarea = container.querySelector('textarea.ace_text-input');
        if (aceTextarea) {
            aceTextarea.setAttribute('aria-label', 'Ace internal input');
        }

        editor.commands.addCommand({
            name: 'mcbrowserSave',
            bindKey: { win: 'Ctrl-S', mac: 'Command-S' },
            exec: () => {
                if (!readOnlyRef.current && onSaveRef.current) {
                    onSaveRef.current();
                }
            },
            readOnly: false,
        });

        const handleEditorChange = () => {
            if (isSyncingValueRef.current) return;
            const nextValue = editor.getValue();
            onChangeRef.current(nextValue);
        };

        const selection = editor.getSelection();
        const handleSelectionChange = () => {
            setIsSelectionEmpty(selection.isEmpty());
        };

        editor.on('change', handleEditorChange);
        selection.on('changeSelection', handleSelectionChange);
        setIsSelectionEmpty(selection.isEmpty());

        editorInstanceRef.current = editor;

        return () => {
            editor.off('change', handleEditorChange);
            selection.off('changeSelection', handleSelectionChange);
            editor.destroy();
            editorInstanceRef.current = null;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        const editor = editorInstanceRef.current;
        if (!editor) return;
        if (editor.getValue() !== value) {
            isSyncingValueRef.current = true;
            try {
                const cursorPosition = editor.getCursorPosition();
                editor.setValue(value, -1);
                editor.moveCursorToPosition(cursorPosition);
                editor.clearSelection();
            } finally {
                isSyncingValueRef.current = false;
            }
        }
    }, [value]);

    useEffect(() => {
        const editor = editorInstanceRef.current;
        if (!editor) return;
        editor.session.setUseWorker(false);
        editor.session.setMode(resolvedMode.mode);
    }, [resolvedMode.mode]);

    useEffect(() => {
        const editor = editorInstanceRef.current;
        if (!editor) return;
        editor.setTheme(resolvedTheme.aceTheme);
    }, [resolvedTheme.aceTheme]);

    useEffect(() => {
        const editor = editorInstanceRef.current;
        if (!editor) return;
        editor.setReadOnly(Boolean(readOnly));
    }, [readOnly]);

    useEffect(() => {
        const editor = editorInstanceRef.current;
        if (!editor) return;
        editor.setFontSize(fontSize);
    }, [fontSize]);

    const handleIncreaseFontSize = useCallback(() => {
        setFontSize((prev) => {
            const next = writePersistedEditorFontSize(clampEditorFontSize(prev + 1));
            editorInstanceRef.current?.setFontSize(next);
            return next;
        });
    }, []);

    const handleDecreaseFontSize = useCallback(() => {
        setFontSize((prev) => {
            const next = writePersistedEditorFontSize(clampEditorFontSize(prev - 1));
            editorInstanceRef.current?.setFontSize(next);
            return next;
        });
    }, []);

    const executeEditorCommand = useCallback(
        async (
            commandName:
                | 'undo'
                | 'redo'
                | 'find'
                | 'replace'
                | 'copy'
                | 'cut'
                | 'paste'
                | 'openCommandPalette'
        ) => {
            const editor = editorInstanceRef.current;
            if (!editor) return;

            setClipboardNotice(null);

            if (
                readOnly &&
                (commandName === 'undo' ||
                    commandName === 'redo' ||
                    commandName === 'replace' ||
                    commandName === 'cut' ||
                    commandName === 'paste')
            ) {
                return;
            }

            if (commandName === 'paste') {
                const pastedText = await readEditorTextFromClipboard();
                if (typeof pastedText === 'string') {
                    editor.execCommand('paste', { text: pastedText });
                    return;
                }
                if (
                    typeof document !== 'undefined' &&
                    typeof document.queryCommandSupported === 'function' &&
                    document.queryCommandSupported('paste')
                ) {
                    document.execCommand('paste');
                } else {
                    setClipboardNotice('Clipboard read is unavailable in this browser context.');
                }
                return;
            }

            if (commandName === 'copy' || commandName === 'cut') {
                const selectedText = editor.getCopyText();
                if (selectedText) {
                    await copyEditorTextToClipboard(selectedText);
                }
                if (commandName === 'cut') {
                    editor.execCommand('cut');
                }
                return;
            }

            editor.execCommand(commandName);
        },
        [readOnly]
    );

    const handleProxyTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        if (readOnly) return;
        const nextVal = e.target.value;
        const editor = editorInstanceRef.current;
        if (editor && editor.getValue() !== nextVal) {
            isSyncingValueRef.current = true;
            try {
                editor.setValue(nextVal, -1);
            } finally {
                isSyncingValueRef.current = false;
            }
        }
        onChange(nextVal);
    };

    const handleContainerKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
            e.preventDefault();
            if (!readOnly && onSave) {
                onSave();
            }
        }
    };

    const toggleMarkdownPreview = () => {
        if (!isMarkdownFile) return;
        setPreviewForPath((prev) => (prev === path ? null : path));
    };

    return (
        <div
            data-testid="mcbrowser-code-editor"
            data-editor-mode={resolvedMode.mode}
            data-editor-mode-name={resolvedMode.name}
            data-editor-mode-fallback={String(resolvedMode.usedFallback)}
            data-editor-theme={resolvedTheme.themeKey}
            data-editor-ace-theme={resolvedTheme.aceTheme}
            data-editor-font-size={String(fontSize)}
            data-editor-readonly={String(Boolean(readOnly))}
            onKeyDown={handleContainerKeyDown}
            className="space-y-2.5"
        >
            <div
                role="toolbar"
                aria-label="Code editor toolbar"
                className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-xs"
            >
                <div className="flex flex-wrap items-center gap-1.5">
                    <span
                        data-testid="mcbrowser-editor-mode-badge"
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md font-mono text-[11px] bg-indigo-500/15 text-indigo-300 border border-indigo-500/30"
                        title={`Ace syntax mode: ${resolvedMode.mode}`}
                    >
                        <FileCode2 size={12} />
                        <span>{resolvedMode.name}</span>
                        {resolvedMode.usedFallback && (
                            <span className="text-[10px] text-amber-300">(text fallback)</span>
                        )}
                    </span>

                    {readOnly && (
                        <span
                            data-testid="mcbrowser-editor-readonly-badge"
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md font-mono text-[11px] bg-amber-500/15 text-amber-300 border border-amber-500/30"
                        >
                            <Lock size={11} />
                            <span>Read-only</span>
                        </span>
                    )}

                    <div
                        role="group"
                        aria-label="Editor font size controls"
                        className="inline-flex items-center gap-1 bg-white/[0.04] border border-white/10 rounded-lg px-1.5 py-0.5"
                    >
                        <button
                            type="button"
                            onClick={handleDecreaseFontSize}
                            disabled={fontSize <= EDITOR_MIN_FONT_SIZE}
                            aria-label="Decrease font size"
                            title="Decrease font size"
                            className="p-1 rounded text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            <Minus size={12} />
                        </button>
                        <span
                            data-testid="mcbrowser-editor-font-size"
                            className="font-mono text-[11px] text-slate-200 min-w-[34px] text-center"
                        >
                            {fontSize}px
                        </span>
                        <button
                            type="button"
                            onClick={handleIncreaseFontSize}
                            disabled={fontSize >= EDITOR_MAX_FONT_SIZE}
                            aria-label="Increase font size"
                            title="Increase font size"
                            className="p-1 rounded text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            <Plus size={12} />
                        </button>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-1">
                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('undo')}
                        disabled={Boolean(readOnly)}
                        aria-label="Undo"
                        title="Undo"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Undo2 size={14} />
                    </button>
                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('redo')}
                        disabled={Boolean(readOnly)}
                        aria-label="Redo"
                        title="Redo"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Redo2 size={14} />
                    </button>

                    <span className="h-4 w-px bg-white/10 mx-0.5" aria-hidden="true" />

                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('find')}
                        aria-label="Find in file"
                        title="Find"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10"
                    >
                        <Search size={14} />
                    </button>
                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('replace')}
                        disabled={Boolean(readOnly)}
                        aria-label="Replace in file"
                        title="Find and Replace"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Replace size={14} />
                    </button>

                    <span className="h-4 w-px bg-white/10 mx-0.5" aria-hidden="true" />

                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('copy')}
                        disabled={isSelectionEmpty}
                        aria-label="Copy selection"
                        title="Copy"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Copy size={14} />
                    </button>
                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('cut')}
                        disabled={isSelectionEmpty || Boolean(readOnly)}
                        aria-label="Cut selection"
                        title="Cut"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <Scissors size={14} />
                    </button>
                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('paste')}
                        disabled={Boolean(readOnly)}
                        aria-label="Paste from clipboard"
                        title="Paste"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <ClipboardPaste size={14} />
                    </button>

                    <button
                        type="button"
                        onClick={() => void executeEditorCommand('openCommandPalette')}
                        aria-label="Open command palette"
                        title="Command Palette"
                        className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/10"
                    >
                        <Terminal size={14} />
                    </button>

                    {onSave && !readOnly && (
                        <button
                            type="button"
                            onClick={onSave}
                            aria-label="Trigger editor save"
                            title="Save (Ctrl+S)"
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-indigo-500/20 border border-indigo-500/35 text-indigo-200 hover:bg-indigo-500/30 font-semibold"
                        >
                            <Save size={13} />
                            <span>Save</span>
                        </button>
                    )}

                    {isMarkdownFile && (
                        <button
                            type="button"
                            onClick={toggleMarkdownPreview}
                            aria-pressed={isPreviewActive}
                            aria-label="Toggle Markdown preview"
                            title={
                                isPreviewActive
                                    ? `Switch to ${fileName || 'Markdown'} source editor`
                                    : `Preview ${fileName || 'Markdown'}`
                            }
                            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-semibold transition-colors ${
                                isPreviewActive
                                    ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/35'
                                    : 'bg-white/[0.06] text-slate-200 border border-white/10 hover:bg-white/10'
                            }`}
                        >
                            {isPreviewActive ? <EyeOff size={13} /> : <Eye size={13} />}
                            <span>{isPreviewActive ? 'Edit Source' : 'Preview'}</span>
                        </button>
                    )}
                </div>
            </div>

            {clipboardNotice && (
                <div
                    role="status"
                    className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-200"
                >
                    {clipboardNotice}
                </div>
            )}

            <label htmlFor="mcbrowser-editor-textarea" className="sr-only">
                UTF-8 File Content
            </label>
            <textarea
                id="mcbrowser-editor-textarea"
                aria-label="UTF-8 File Content"
                data-editor-theme={resolvedTheme.themeKey}
                value={value}
                onChange={handleProxyTextareaChange}
                readOnly={Boolean(readOnly)}
                disabled={Boolean(readOnly)}
                rows={1}
                className="sr-only"
            />

            {isMarkdownFile && isPreviewActive && (
                <div
                    data-testid="mcbrowser-markdown-preview-panel"
                    className="rounded-xl border border-white/15 bg-slate-950/90 p-4 min-h-[320px] max-h-[520px] overflow-y-auto space-y-3"
                >
                    {previewResult.error ? (
                        <div
                            role="alert"
                            data-testid="mcbrowser-markdown-preview-error"
                            className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2"
                        >
                            <AlertTriangle size={16} className="text-rose-400 shrink-0 mt-0.5" />
                            <div>
                                <p className="font-semibold">Markdown preview failed to render</p>
                                <p className="text-rose-200/90 mt-0.5">{previewResult.error}</p>
                            </div>
                        </div>
                    ) : previewResult.html ? (
                        <div
                            data-testid="mcbrowser-markdown-preview-content"
                            className="prose prose-invert max-w-none text-sm text-slate-100 leading-relaxed space-y-2"
                            style={{ fontSize: `${fontSize}px` }}
                            dangerouslySetInnerHTML={{ __html: previewResult.html }}
                        />
                    ) : (
                        <p
                            data-testid="mcbrowser-markdown-preview-empty"
                            className="text-xs text-slate-400 italic"
                        >
                            Nothing to preview — enter Markdown content in the editor.
                        </p>
                    )}
                </div>
            )}

            <div
                className={`rounded-xl border overflow-hidden ${getThemeSurfaceClasses(
                    resolvedTheme.themeKey
                )} ${isPreviewActive ? 'hidden' : 'block'}`}
            >
                <div
                    ref={aceContainerRef}
                    data-testid="mcbrowser-ace-surface"
                    className="w-full min-h-[320px] h-[360px]"
                />
            </div>
        </div>
    );
}
