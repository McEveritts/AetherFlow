'use client';

import { useId, useState, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

export default function ResponsiveSummary({ label, children }: { label: string; children: ReactNode }) {
    const contentId = useId();
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="min-w-0">
            <button
                type="button"
                aria-expanded={expanded}
                aria-controls={contentId}
                onClick={() => setExpanded(current => !current)}
                className="md:hidden obs-touch-target-standard min-h-[44px] w-full min-w-0 flex items-center justify-between gap-3 border-b border-white/[0.07] px-3 py-2.5 text-left text-xs font-semibold text-slate-300 hover:text-white focus-visible:outline-2 focus-visible:outline-indigo-400"
            >
                <span className="min-w-0 break-words">{label}</span>
                <ChevronDown aria-hidden="true" size={16} className={`shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`} />
            </button>
            <div id={contentId} className={`${expanded ? 'block' : 'hidden'} md:block min-w-0`}>
                {children}
            </div>
        </div>
    );
}
