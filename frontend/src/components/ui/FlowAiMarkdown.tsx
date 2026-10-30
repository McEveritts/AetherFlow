import React, { useState } from 'react';
import { Copy, Check, Terminal } from 'lucide-react';

interface FlowAiMarkdownProps {
    content: string;
    className?: string;
}

type BlockNode =
    | { type: 'heading'; level: number; text: string }
    | { type: 'code'; lang: string; code: string }
    | { type: 'hr' }
    | { type: 'blockquote'; lines: string[] }
    | { type: 'ul'; items: string[] }
    | { type: 'ol'; items: { num: number; text: string }[] }
    | { type: 'table'; headers: string[]; rows: string[][] }
    | { type: 'p'; text: string };

function CodeBlock({ lang, code }: { lang: string; code: string }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // Clipboard fallback ignored
        }
    };

    const displayLang = lang ? lang.toLowerCase() : 'shell';

    return (
        <div className="my-3.5 rounded-xl overflow-hidden border border-white/10 bg-slate-950/90 shadow-inner">
            <div className="flex items-center justify-between px-3.5 py-2 bg-white/[0.04] border-b border-white/[0.07]">
                <div className="flex items-center gap-2 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                    <Terminal size={12} className="text-indigo-400" />
                    <span>{displayLang}</span>
                </div>
                <button
                    type="button"
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px] font-medium text-slate-400 hover:text-white hover:bg-white/[0.08] transition-colors cursor-pointer"
                    title="Copy code"
                >
                    {copied ? (
                        <>
                            <Check size={12} className="text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                        </>
                    ) : (
                        <>
                            <Copy size={12} />
                            <span>Copy</span>
                        </>
                    )}
                </button>
            </div>
            <pre className="p-3.5 overflow-x-auto text-xs font-mono text-slate-200 leading-relaxed custom-scrollbar">
                <code>{code}</code>
            </pre>
        </div>
    );
}

const INLINE_TOKEN_REGEX =
    /(`[^`\n]+`)|(\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/[^\s)]*|#[^\s)]*)\))|(\*\*\*((?:`[^`\n]*`|(?!\*\*\*)[^\n])+?)\*\*\*)|(\*\*((?:`[^`\n]*`|(?!\*\*)[^\n])+?)\*\*)|(__(?:`[^`\n]*`|(?!__)[^\n])+?__)|(~~((?:`[^`\n]*`|(?!~~)[^\n])+?)~~)|(\*((?:`[^`\n]*`|[^*\n])+?)\*)|((?:^|(?<=[\s(]))_((?:`[^`\n]*`|[^_\n])+?)_(?=$|[\s.,!?:;)]))|(https?:\/\/[^\s<>()]+?(?=[.,!?:;)]*(?:\s|$)))/g;

export function renderInlineMarkdown(text: string, keyPrefix = 'inl'): React.ReactNode[] {
    if (!text) return [];

    const nodes: React.ReactNode[] = [];
    let lastIndex = 0;
    let match: RegExpExecArray | null;
    const regex = new RegExp(INLINE_TOKEN_REGEX.source, 'g');
    let tokenIdx = 0;

    while ((match = regex.exec(text)) !== null) {
        if (match.index > lastIndex) {
            nodes.push(text.slice(lastIndex, match.index));
        }

        const key = `${keyPrefix}-${tokenIdx++}`;

        if (match[1]) {
            // Inline code: `code`
            const codeContent = match[1].slice(1, -1);
            nodes.push(
                <code
                    key={key}
                    className="px-1.5 py-0.5 mx-0.5 rounded-md bg-indigo-500/10 border border-indigo-400/20 font-mono text-[12px] text-indigo-200"
                >
                    {codeContent}
                </code>
            );
        } else if (match[2]) {
            // Link: [label](url)
            const label = match[3];
            const url = match[4];
            nodes.push(
                <a
                    key={key}
                    href={url}
                    target={url.startsWith('http') ? '_blank' : undefined}
                    rel={url.startsWith('http') ? 'noopener noreferrer' : undefined}
                    className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2 font-medium transition-colors"
                >
                    {renderInlineMarkdown(label, `${key}-lnk`)}
                </a>
            );
        } else if (match[5]) {
            // Bold + Italic: ***text***
            const inner = match[6];
            nodes.push(
                <strong key={key} className="font-semibold italic text-white">
                    {renderInlineMarkdown(inner, `${key}-bi`)}
                </strong>
            );
        } else if (match[7]) {
            // Bold: **text**
            const inner = match[8];
            nodes.push(
                <strong key={key} className="font-semibold text-white">
                    {renderInlineMarkdown(inner, `${key}-b`)}
                </strong>
            );
        } else if (match[9]) {
            // Bold: __text__
            const inner = match[9].slice(2, -2);
            nodes.push(
                <strong key={key} className="font-semibold text-white">
                    {renderInlineMarkdown(inner, `${key}-bu`)}
                </strong>
            );
        } else if (match[10]) {
            // Strikethrough: ~~text~~
            const inner = match[11];
            nodes.push(
                <del key={key} className="line-through text-slate-400">
                    {renderInlineMarkdown(inner, `${key}-del`)}
                </del>
            );
        } else if (match[12]) {
            // Italic: *text*
            const inner = match[13];
            nodes.push(
                <em key={key} className="italic text-slate-100">
                    {renderInlineMarkdown(inner, `${key}-i`)}
                </em>
            );
        } else if (match[14]) {
            // Italic: _text_
            const inner = match[15];
            nodes.push(
                <em key={key} className="italic text-slate-100">
                    {renderInlineMarkdown(inner, `${key}-iu`)}
                </em>
            );
        } else if (match[16]) {
            // Bare URL: https://...
            const url = match[16];
            nodes.push(
                <a
                    key={key}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2 font-medium transition-colors break-all"
                >
                    {url}
                </a>
            );
        }

        lastIndex = regex.lastIndex;
    }

    if (lastIndex < text.length) {
        nodes.push(text.slice(lastIndex));
    }

    return nodes;
}

function isTableSeparator(line: string): boolean {
    const trimmed = line.trim();
    if (!trimmed.includes('|') || !trimmed.includes('-')) return false;
    return /^\|?[\s:|-]+\|[\s:|-]*$/.test(trimmed);
}

function splitTableRow(line: string): string[] {
    const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
    return trimmed.split('|').map((cell) => cell.trim());
}

export function parseMarkdownBlocks(raw: string): BlockNode[] {
    const lines = raw.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').split('\n');
    const blocks: BlockNode[] = [];
    let i = 0;

    const isBlockStarter = (idx: number): boolean => {
        if (idx >= lines.length) return false;
        const l = lines[idx];
        const trimmed = l.trim();
        if (!trimmed) return true;
        if (/^(?:```|~~~)/.test(trimmed)) return true;
        if (/^(?:---|\*\*\*|___)\s*$/.test(trimmed)) return true;
        if (/^#{1,6}\s+/.test(trimmed)) return true;
        if (/^>\s?/.test(trimmed)) return true;
        if (/^\s*[*+-]\s+/.test(l)) return true;
        if (/^\s*\d+\.\s+/.test(l)) return true;
        if (trimmed.includes('|') && idx + 1 < lines.length && isTableSeparator(lines[idx + 1])) return true;
        return false;
    };

    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();

        // 1. Blank line
        if (!trimmed) {
            i++;
            continue;
        }

        // 2. Fenced code block
        const fenceMatch = trimmed.match(/^(```|~~~)([\w-]*)\s*$/);
        if (fenceMatch) {
            const fence = fenceMatch[1];
            const lang = fenceMatch[2] || '';
            const codeLines: string[] = [];
            i++;
            while (i < lines.length && !lines[i].trim().startsWith(fence)) {
                codeLines.push(lines[i]);
                i++;
            }
            if (i < lines.length) i++; // consume closing fence
            blocks.push({ type: 'code', lang, code: codeLines.join('\n') });
            continue;
        }

        // 3. Horizontal rule
        if (/^(?:---|\*\*\*|___)\s*$/.test(trimmed)) {
            blocks.push({ type: 'hr' });
            i++;
            continue;
        }

        // 4. Heading
        const headingMatch = trimmed.match(/^(#{1,6})\s+(.+)$/);
        if (headingMatch) {
            blocks.push({
                type: 'heading',
                level: headingMatch[1].length,
                text: headingMatch[2].trim(),
            });
            i++;
            continue;
        }

        // 5. Table
        if (trimmed.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
            const headers = splitTableRow(lines[i]);
            i += 2; // skip header and separator
            const rows: string[][] = [];
            while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
                rows.push(splitTableRow(lines[i]));
                i++;
            }
            blocks.push({ type: 'table', headers, rows });
            continue;
        }

        // 6. Blockquote
        if (/^>\s?/.test(trimmed)) {
            const quoteLines: string[] = [];
            while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
                quoteLines.push(lines[i].trim().replace(/^>\s?/, ''));
                i++;
            }
            blocks.push({ type: 'blockquote', lines: quoteLines });
            continue;
        }

        // 7. Unordered list
        if (/^\s*[*+-]\s+/.test(line)) {
            const items: string[] = [];
            while (i < lines.length) {
                const ulMatch = lines[i].match(/^\s*[*+-]\s+(.+)$/);
                if (ulMatch) {
                    items.push(ulMatch[1].trim());
                    i++;
                    // Continuation lines indented under the list item
                    while (
                        i < lines.length &&
                        lines[i].trim() !== '' &&
                        !isBlockStarter(i) &&
                        /^\s{2,}/.test(lines[i])
                    ) {
                        items[items.length - 1] += ' ' + lines[i].trim();
                        i++;
                    }
                } else {
                    break;
                }
            }
            blocks.push({ type: 'ul', items });
            continue;
        }

        // 8. Ordered list
        if (/^\s*\d+\.\s+/.test(line)) {
            const items: { num: number; text: string }[] = [];
            while (i < lines.length) {
                const olMatch = lines[i].match(/^\s*(\d+)\.\s+(.+)$/);
                if (olMatch) {
                    items.push({
                        num: parseInt(olMatch[1], 10),
                        text: olMatch[2].trim(),
                    });
                    i++;
                    while (
                        i < lines.length &&
                        lines[i].trim() !== '' &&
                        !isBlockStarter(i) &&
                        /^\s{2,}/.test(lines[i])
                    ) {
                        items[items.length - 1].text += ' ' + lines[i].trim();
                        i++;
                    }
                } else {
                    break;
                }
            }
            blocks.push({ type: 'ol', items });
            continue;
        }

        // 9. Paragraph
        const paraLines: string[] = [];
        while (i < lines.length && !isBlockStarter(i)) {
            paraLines.push(lines[i].trim());
            i++;
        }
        if (paraLines.length > 0) {
            blocks.push({ type: 'p', text: paraLines.join(' ') });
        } else {
            // Fallback safety to avoid infinite loops
            blocks.push({ type: 'p', text: trimmed });
            i++;
        }
    }

    return blocks;
}

export default function FlowAiMarkdown({ content, className = '' }: FlowAiMarkdownProps) {
    const blocks = parseMarkdownBlocks(content);

    return (
        <div className={`space-y-3 text-sm leading-relaxed text-slate-200 ${className}`}>
            {blocks.map((block, idx) => {
                const key = `blk-${idx}`;

                switch (block.type) {
                    case 'heading': {
                        const children = renderInlineMarkdown(block.text, key);
                        if (block.level === 1) {
                            return (
                                <h1 key={key} className="text-lg font-bold text-white tracking-tight pt-2 pb-1 border-b border-white/10 first:pt-0">
                                    {children}
                                </h1>
                            );
                        }
                        if (block.level === 2) {
                            return (
                                <h2 key={key} className="text-base font-bold text-white tracking-tight pt-2 pb-1 border-b border-white/[0.08] first:pt-0">
                                    {children}
                                </h2>
                            );
                        }
                        if (block.level === 3) {
                            return (
                                <h3 key={key} className="text-[15px] font-bold text-slate-100 tracking-tight pt-2 first:pt-0">
                                    {children}
                                </h3>
                            );
                        }
                        return (
                            <h4 key={key} className="text-sm font-semibold text-indigo-300 pt-1.5 first:pt-0">
                                {children}
                            </h4>
                        );
                    }

                    case 'code':
                        return <CodeBlock key={key} lang={block.lang} code={block.code} />;

                    case 'hr':
                        return <hr key={key} className="my-4 border-t border-white/10" />;

                    case 'blockquote':
                        return (
                            <blockquote
                                key={key}
                                className="border-l-2 border-indigo-400/50 bg-indigo-500/[0.06] pl-3.5 pr-3 py-2 rounded-r-xl text-slate-300 space-y-1"
                            >
                                {block.lines.map((line, lIdx) => (
                                    <p key={`${key}-q-${lIdx}`} className="text-xs leading-relaxed">
                                        {renderInlineMarkdown(line, `${key}-q-${lIdx}`)}
                                    </p>
                                ))}
                            </blockquote>
                        );

                    case 'ul':
                        return (
                            <ul key={key} className="space-y-2 my-2 pl-1">
                                {block.items.map((item, itemIdx) => (
                                    <li key={`${key}-li-${itemIdx}`} className="flex items-start gap-2.5 text-slate-200 leading-relaxed">
                                        <span className="mt-2 h-1.5 w-1.5 rounded-full bg-indigo-400 shrink-0" />
                                        <span className="flex-1 min-w-0">
                                            {renderInlineMarkdown(item, `${key}-li-${itemIdx}`)}
                                        </span>
                                    </li>
                                ))}
                            </ul>
                        );

                    case 'ol':
                        return (
                            <ol key={key} className="space-y-2.5 my-2 pl-0.5">
                                {block.items.map((item, itemIdx) => (
                                    <li key={`${key}-oli-${itemIdx}`} className="flex items-start gap-2.5 text-slate-200 leading-relaxed">
                                        <span className="mt-0.5 h-5 min-w-5 px-1 rounded-md bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 text-xs font-bold flex items-center justify-center shrink-0">
                                            {item.num}
                                        </span>
                                        <span className="flex-1 min-w-0">
                                            {renderInlineMarkdown(item.text, `${key}-oli-${itemIdx}`)}
                                        </span>
                                    </li>
                                ))}
                            </ol>
                        );

                    case 'table':
                        return (
                            <div key={key} className="my-3 overflow-x-auto rounded-xl border border-white/10 bg-slate-950/50">
                                <table className="w-full text-left border-collapse text-xs">
                                    <thead>
                                        <tr className="bg-white/[0.04] border-b border-white/10 text-slate-200 font-semibold">
                                            {block.headers.map((header, hIdx) => (
                                                <th key={`${key}-th-${hIdx}`} className="px-3.5 py-2.5">
                                                    {renderInlineMarkdown(header, `${key}-th-${hIdx}`)}
                                                </th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/[0.06]">
                                        {block.rows.map((row, rIdx) => (
                                            <tr key={`${key}-tr-${rIdx}`} className="hover:bg-white/[0.02]">
                                                {row.map((cell, cIdx) => (
                                                    <td key={`${key}-td-${rIdx}-${cIdx}`} className="px-3.5 py-2 text-slate-300">
                                                        {renderInlineMarkdown(cell, `${key}-td-${rIdx}-${cIdx}`)}
                                                    </td>
                                                ))}
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        );

                    case 'p':
                    default:
                        return (
                            <p key={key} className="leading-relaxed text-slate-200">
                                {renderInlineMarkdown(block.text, key)}
                            </p>
                        );
                }
            })}
        </div>
    );
}
