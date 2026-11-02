import { Marked } from 'marked';
import markedKatex from 'marked-katex-extension';
import DOMPurify from 'dompurify';

export const EDITOR_MIN_FONT_SIZE = 8;
export const EDITOR_MAX_FONT_SIZE = 40;
export const EDITOR_DEFAULT_FONT_SIZE = 14;
export const EDITOR_FONT_SIZE_STORAGE_KEY = 'editorFontSize';

export const MCBROWSER_BUNDLED_ACE_MODES = [
    'text',
    'javascript',
    'typescript',
    'tsx',
    'jsx',
    'json',
    'json5',
    'markdown',
    'html',
    'css',
    'scss',
    'less',
    'python',
    'rust',
    'golang',
    'c_cpp',
    'java',
    'csharp',
    'php',
    'ruby',
    'sh',
    'batchfile',
    'powershell',
    'yaml',
    'toml',
    'ini',
    'properties',
    'xml',
    'svg',
    'sql',
    'dockerfile',
    'makefile',
    'gitignore',
    'diff',
    'lua',
    'perl',
    'swift',
    'kotlin',
    'scala',
    'graphqlschema',
    'prisma',
    'terraform',
    'nginx',
    'apache_conf',
    'latex',
    'tex',
] as const;

export type McBrowserBundledAceModeName = (typeof MCBROWSER_BUNDLED_ACE_MODES)[number];

export const MCBROWSER_BUNDLED_ACE_THEMES = [
    'chrome',
    'github',
    'solarized_light',
    'monokai',
    'dracula',
    'twilight',
    'tomorrow_night',
    'solarized_dark',
    'textmate',
    'clouds',
    'dawn',
    'eclipse',
    'xcode',
    'nord_dark',
    'one_dark',
    'terminal',
    'github_dark',
] as const;

export type McBrowserBundledAceThemeName = (typeof MCBROWSER_BUNDLED_ACE_THEMES)[number];

const BUNDLED_MODES_SET: ReadonlySet<string> = new Set(MCBROWSER_BUNDLED_ACE_MODES);
const BUNDLED_THEMES_SET: ReadonlySet<string> = new Set(MCBROWSER_BUNDLED_ACE_THEMES);

interface FallbackModeRule {
    pattern: RegExp;
    mode: McBrowserBundledAceModeName;
}

const FALLBACK_FILENAME_MODE_RULES: readonly FallbackModeRule[] = [
    { pattern: /^dockerfile(?:\..+)?$/i, mode: 'dockerfile' },
    { pattern: /^(?:makefile|gnumakefile|ocamlmakefile)$/i, mode: 'makefile' },
    { pattern: /^\.gitignore$/i, mode: 'gitignore' },
    { pattern: /^\.(?:bashrc|bash_profile|profile|zshrc|shrc)$/i, mode: 'sh' },
    { pattern: /^\.env(?:\..+)?$/i, mode: 'ini' },
    { pattern: /^(?:htaccess|htgroups|htpasswd|\.htaccess|\.htgroups|\.htpasswd)$/i, mode: 'apache_conf' },
    { pattern: /\.(?:md|markdown)$/i, mode: 'markdown' },
    { pattern: /\.(?:ts|mts|cts|typescript)$/i, mode: 'typescript' },
    { pattern: /\.tsx$/i, mode: 'tsx' },
    { pattern: /\.jsx$/i, mode: 'jsx' },
    { pattern: /\.(?:js|jsm|cjs|mjs)$/i, mode: 'javascript' },
    { pattern: /\.json5$/i, mode: 'json5' },
    { pattern: /\.json$/i, mode: 'json' },
    { pattern: /\.(?:yaml|yml)$/i, mode: 'yaml' },
    { pattern: /\.toml$/i, mode: 'toml' },
    { pattern: /\.properties$/i, mode: 'properties' },
    { pattern: /\.nginx$/i, mode: 'nginx' },
    { pattern: /\.(?:ini|conf|cfg|prefs)$/i, mode: 'ini' },
    { pattern: /\.(?:html|htm|xhtml)$/i, mode: 'html' },
    { pattern: /\.scss$/i, mode: 'scss' },
    { pattern: /\.less$/i, mode: 'less' },
    { pattern: /\.css$/i, mode: 'css' },
    { pattern: /\.py$/i, mode: 'python' },
    { pattern: /\.rs$/i, mode: 'rust' },
    { pattern: /\.go$/i, mode: 'golang' },
    { pattern: /\.(?:cpp|c|cc|cxx|h|hh|hpp|ino)$/i, mode: 'c_cpp' },
    { pattern: /\.java$/i, mode: 'java' },
    { pattern: /\.cs$/i, mode: 'csharp' },
    { pattern: /\.php$/i, mode: 'php' },
    { pattern: /\.(?:rb|ru|gemspec|rake)$/i, mode: 'ruby' },
    { pattern: /\.(?:sh|bash)$/i, mode: 'sh' },
    { pattern: /\.(?:bat|cmd)$/i, mode: 'batchfile' },
    { pattern: /\.ps1$/i, mode: 'powershell' },
    { pattern: /\.svg$/i, mode: 'svg' },
    { pattern: /\.(?:xml|rdf|rss|wsdl|xslt|atom|mathml|mml|xul|xbl|xaml)$/i, mode: 'xml' },
    { pattern: /\.sql$/i, mode: 'sql' },
    { pattern: /\.(?:diff|patch)$/i, mode: 'diff' },
    { pattern: /\.lua$/i, mode: 'lua' },
    { pattern: /\.(?:pl|pm)$/i, mode: 'perl' },
    { pattern: /\.swift$/i, mode: 'swift' },
    { pattern: /\.(?:kt|kts)$/i, mode: 'kotlin' },
    { pattern: /\.(?:scala|sbt)$/i, mode: 'scala' },
    { pattern: /\.gql$/i, mode: 'graphqlschema' },
    { pattern: /\.prisma$/i, mode: 'prisma' },
    { pattern: /\.(?:tf|tfvars|terragrunt)$/i, mode: 'terraform' },
    { pattern: /\.(?:tex|latex|ltx|bib)$/i, mode: 'latex' },
    { pattern: /\.txt$/i, mode: 'text' },
];

export interface AceModelistLike {
    getModeForPath?: (path: string) => { mode?: string; name?: string } | null | undefined;
}

export interface AceThemelistLike {
    themesByName?: Record<string, { theme?: string; name?: string; isDark?: boolean } | undefined>;
}

export interface ResolvedAceMode {
    mode: string;
    name: McBrowserBundledAceModeName;
    detectedMode: string;
    usedFallback: boolean;
}

export function extractEditorFileName(path: string): string {
    if (!path || typeof path !== 'string') return '';
    const trimmed = path.trim();
    if (!trimmed) return '';
    const parts = trimmed.split(/[/\\]/);
    return parts[parts.length - 1] || '';
}

export function isMarkdownEditorPath(path: string): boolean {
    const fileName = extractEditorFileName(path).toLowerCase();
    return fileName.endsWith('.md') || fileName.endsWith('.markdown');
}

export function resolveMcBrowserEditorMode(
    path: string,
    modelist?: AceModelistLike | null
): ResolvedAceMode {
    const fileName = extractEditorFileName(path);
    if (!fileName) {
        return {
            mode: 'ace/mode/text',
            name: 'text',
            detectedMode: 'ace/mode/text',
            usedFallback: false,
        };
    }

    if (/^\.env(?:\..+)?$/i.test(fileName)) {
        return {
            mode: 'ace/mode/ini',
            name: 'ini',
            detectedMode: 'ace/mode/ini',
            usedFallback: false,
        };
    }

    let rawMode = '';
    if (modelist && typeof modelist.getModeForPath === 'function') {
        try {
            const matched = modelist.getModeForPath(fileName);
            if (matched && typeof matched.mode === 'string' && matched.mode.trim()) {
                rawMode = matched.mode.trim();
            }
        } catch {
            rawMode = '';
        }
    }

    if (!rawMode) {
        for (const rule of FALLBACK_FILENAME_MODE_RULES) {
            if (rule.pattern.test(fileName)) {
                rawMode = `ace/mode/${rule.mode}`;
                break;
            }
        }
    }

    if (!rawMode) {
        rawMode = 'ace/mode/text';
    }

    const normalizedName = rawMode.replace(/^ace\/mode\//, '').toLowerCase();
    if (BUNDLED_MODES_SET.has(normalizedName)) {
        return {
            mode: `ace/mode/${normalizedName}`,
            name: normalizedName as McBrowserBundledAceModeName,
            detectedMode: rawMode,
            usedFallback: false,
        };
    }

    for (const rule of FALLBACK_FILENAME_MODE_RULES) {
        if (rule.pattern.test(fileName)) {
            return {
                mode: `ace/mode/${rule.mode}`,
                name: rule.mode,
                detectedMode: rawMode,
                usedFallback: false,
            };
        }
    }

    return {
        mode: 'ace/mode/text',
        name: 'text',
        detectedMode: rawMode,
        usedFallback: normalizedName !== 'text',
    };
}

export interface ResolvedAceTheme {
    aceTheme: string;
    themeKey: McBrowserBundledAceThemeName;
}

export function resolveMcBrowserEditorTheme(
    themeInput?: string | null,
    options?: {
        preferDarkFallback?: boolean;
        themelist?: AceThemelistLike | null;
    }
): ResolvedAceTheme {
    const raw = typeof themeInput === 'string' ? themeInput.trim() : '';
    const cleaned = raw.replace(/^ace\/theme\//i, '').toLowerCase();

    const isKnownInThemelist =
        !options?.themelist?.themesByName ||
        Boolean(cleaned && options.themelist.themesByName[cleaned]);

    if (cleaned && BUNDLED_THEMES_SET.has(cleaned) && isKnownInThemelist) {
        return {
            aceTheme: `ace/theme/${cleaned}`,
            themeKey: cleaned as McBrowserBundledAceThemeName,
        };
    }

    const fallbackKey: McBrowserBundledAceThemeName = options?.preferDarkFallback
        ? 'twilight'
        : 'chrome';
    return {
        aceTheme: `ace/theme/${fallbackKey}`,
        themeKey: fallbackKey,
    };
}

export function clampEditorFontSize(size: unknown): number {
    const parsed = typeof size === 'number' ? size : Number.parseInt(String(size ?? ''), 10);
    if (!Number.isFinite(parsed)) {
        return EDITOR_DEFAULT_FONT_SIZE;
    }
    const rounded = Math.round(parsed);
    if (rounded < EDITOR_MIN_FONT_SIZE) return EDITOR_MIN_FONT_SIZE;
    if (rounded > EDITOR_MAX_FONT_SIZE) return EDITOR_MAX_FONT_SIZE;
    return rounded;
}

export interface StorageLike {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
}

function getSafeLocalStorage(customStorage?: StorageLike | null): StorageLike | null {
    if (customStorage) return customStorage;
    if (typeof window === 'undefined') return null;
    try {
        return window.localStorage ?? null;
    } catch {
        return null;
    }
}

export function readPersistedEditorFontSize(customStorage?: StorageLike | null): number {
    const storage = getSafeLocalStorage(customStorage);
    if (!storage) return EDITOR_DEFAULT_FONT_SIZE;
    try {
        const raw = storage.getItem(EDITOR_FONT_SIZE_STORAGE_KEY);
        if (raw === null || raw.trim() === '') return EDITOR_DEFAULT_FONT_SIZE;
        return clampEditorFontSize(raw);
    } catch {
        return EDITOR_DEFAULT_FONT_SIZE;
    }
}

export function writePersistedEditorFontSize(
    size: number,
    customStorage?: StorageLike | null
): number {
    const clamped = clampEditorFontSize(size);
    const storage = getSafeLocalStorage(customStorage);
    if (storage) {
        try {
            storage.setItem(EDITOR_FONT_SIZE_STORAGE_KEY, String(clamped));
        } catch {
            return clamped;
        }
    }
    return clamped;
}

export interface SafeMarkdownRenderResult {
    html: string;
    error: string | null;
}

export function createIsolatedMarkdownInstance(): Marked {
    const instance = new Marked({
        gfm: true,
        breaks: false,
    });
    instance.use(
        markedKatex({
            output: 'mathml',
            trust: false,
            throwOnError: false,
            strict: 'ignore',
        })
    );
    return instance;
}

const FORBIDDEN_PREVIEW_TAGS = [
    'script',
    'style',
    'iframe',
    'frame',
    'frameset',
    'object',
    'embed',
    'applet',
    'form',
    'input',
    'button',
    'textarea',
    'select',
    'option',
    'meta',
    'link',
    'base',
    'svg',
    'audio',
    'video',
    'source',
    'track',
    'picture',
    'img',
    'image',
    'canvas',
    'noscript',
    'template',
];

const FORBIDDEN_PREVIEW_ATTRS = [
    'style',
    'src',
    'srcset',
    'Ping',
    'ping',
    'formaction',
    'xlink:href',
    'action',
    'background',
    'poster',
    'dynsrc',
    'lowsrc',
];

const ALLOWED_SAFE_URI_REGEXP = /^(?:https?:|mailto:|tel:|#|\/(?!\/))/i;

function postSanitizeDomTree(root: ParentNode): void {
    const elements = root.querySelectorAll('*');
    elements.forEach((el) => {
        const tag = el.tagName.toLowerCase();
        if (FORBIDDEN_PREVIEW_TAGS.includes(tag)) {
            el.remove();
            return;
        }

        const attrNames = el.getAttributeNames();
        for (const attr of attrNames) {
            const lowerAttr = attr.toLowerCase();
            const val = el.getAttribute(attr) ?? '';

            if (
                lowerAttr.startsWith('on') ||
                lowerAttr.startsWith('data-') ||
                FORBIDDEN_PREVIEW_ATTRS.includes(lowerAttr)
            ) {
                el.removeAttribute(attr);
                continue;
            }

            if (lowerAttr === 'href') {
                const trimmed = val.trim();
                const normalized = trimmed.replace(/[\u0000-\u0020]+/g, '');
                if (!normalized || !ALLOWED_SAFE_URI_REGEXP.test(normalized)) {
                    el.removeAttribute(attr);
                } else {
                    if (/^https?:/i.test(normalized)) {
                        el.setAttribute('target', '_blank');
                        el.setAttribute('rel', 'noopener noreferrer');
                    }
                }
            }
        }
    });
}

export function renderSafeMarkdownPreview(
    markdownSource: string,
    options?: {
        customMarked?: { parse: (src: string) => string | Promise<string> };
    }
): SafeMarkdownRenderResult {
    if (typeof markdownSource !== 'string') {
        return { html: '', error: null };
    }
    if (!markdownSource.trim()) {
        return { html: '', error: null };
    }

    try {
        const parser = options?.customMarked ?? createIsolatedMarkdownInstance();
        const rawRendered = parser.parse(markdownSource);
        if (typeof rawRendered !== 'string') {
            throw new Error('Asynchronous markdown parser is not supported in synchronous preview.');
        }

        if (typeof window === 'undefined' || typeof document === 'undefined') {
            return { html: '', error: null };
        }

        const purify =
            typeof DOMPurify.sanitize === 'function'
                ? DOMPurify
                : typeof DOMPurify === 'function'
                ? (DOMPurify as unknown as (win: Window) => typeof DOMPurify)(window)
                : null;

        if (!purify || typeof purify.sanitize !== 'function') {
            throw new Error('DOMPurify sanitizer is unavailable in the current environment.');
        }

        const sanitized = purify.sanitize(rawRendered, {
            USE_PROFILES: { html: true, mathMl: true },
            ADD_TAGS: [
                'semantics',
                'annotation',
                'mrow',
                'mi',
                'mn',
                'mo',
                'msup',
                'msub',
                'msubsup',
                'mfrac',
                'msqrt',
                'mroot',
                'mtable',
                'mtr',
                'mtd',
                'mtext',
                'mspace',
                'mover',
                'munder',
                'munderover',
                'mpadded',
                'mphantom',
                'menclose',
            ],
            ADD_ATTR: [
                'encoding',
                'display',
                'xmlns',
                'mathvariant',
                'stretchy',
                'fence',
                'separator',
                'accent',
                'accentunder',
                'columnalign',
                'rowalign',
                'columnspacing',
                'rowspacing',
                'columnlines',
                'rowlines',
                'frame',
                'framespacing',
                'equalrows',
                'equalcolumns',
                'displaystyle',
                'scriptlevel',
                'linethickness',
                'lspace',
                'rspace',
                'maxsize',
                'minsize',
                'movablelimits',
                'symmetric',
                'voffset',
                'width',
                'height',
                'depth',
                'columnspan',
                'rowspan',
            ],
            FORBID_TAGS: FORBIDDEN_PREVIEW_TAGS,
            FORBID_ATTR: FORBIDDEN_PREVIEW_ATTRS,
            ALLOW_DATA_ATTR: false,
            ALLOW_UNKNOWN_PROTOCOLS: false,
            ALLOWED_URI_REGEXP: ALLOWED_SAFE_URI_REGEXP,
        });

        const template = document.createElement('template');
        template.innerHTML = sanitized;
        postSanitizeDomTree(template.content);

        return {
            html: template.innerHTML,
            error: null,
        };
    } catch (err) {
        const message =
            err instanceof Error && err.message
                ? err.message
                : 'Failed to convert Markdown content to safe HTML preview.';
        return {
            html: '',
            error: message,
        };
    }
}

export async function copyEditorTextToClipboard(text: string): Promise<boolean> {
    if (!text || typeof window === 'undefined' || typeof document === 'undefined') {
        return false;
    }

    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            void err;
        }
    }

    try {
        if (
            typeof document.queryCommandSupported === 'function' &&
            !document.queryCommandSupported('copy')
        ) {
            return false;
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.top = '0';
        textarea.style.left = '0';
        textarea.style.width = '1px';
        textarea.style.height = '1px';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        try {
            textarea.focus();
            textarea.select();
            return Boolean(document.execCommand?.('copy'));
        } finally {
            document.body.removeChild(textarea);
        }
    } catch {
        return false;
    }
}

export async function readEditorTextFromClipboard(): Promise<string | null> {
    if (typeof window === 'undefined' || typeof navigator === 'undefined') {
        return null;
    }
    if (navigator.clipboard?.readText) {
        try {
            return await navigator.clipboard.readText();
        } catch {
            return null;
        }
    }
    return null;
}
