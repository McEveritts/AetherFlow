'use client';

import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown, Check } from 'lucide-react';

export interface GlassSelectOption {
    value: string;
    label: string;
    description?: string;
    badge?: string;
    badgeVariant?: 'emerald' | 'amber' | 'indigo' | 'slate';
    dotColor?: string;
    group?: string;
}

export interface GlassSelectProps {
    value: string;
    onChange: (value: string) => void;
    options: GlassSelectOption[];
    ariaLabel?: string;
    className?: string;
}

const BADGE_STYLES: Record<NonNullable<GlassSelectOption['badgeVariant']>, string> = {
    emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    indigo: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
    slate: 'bg-slate-800/90 text-slate-300 border-white/10',
};

export default function GlassSelect({
    value,
    onChange,
    options,
    ariaLabel,
    className = '',
}: GlassSelectProps) {
    const [isOpen, setIsOpen] = useState(false);
    const containerRef = useRef<HTMLDivElement>(null);

    const selectedOption = options.find((opt) => opt.value === value) || options[0];

    useEffect(() => {
        const handleClickOutside = (event: PointerEvent | MouseEvent) => {
            if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setIsOpen(false);
            }
        };
        document.addEventListener('pointerdown', handleClickOutside);
        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('pointerdown', handleClickOutside);
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, []);

    const handleSelect = (optionValue: string) => {
        onChange(optionValue);
        setIsOpen(false);
    };

    // Group options if any option specifies a group
    const hasGroups = options.some((opt) => Boolean(opt.group));
    const groupedOptions = hasGroups
        ? options.reduce<Record<string, GlassSelectOption[]>>((acc, opt) => {
              const groupName = opt.group || 'Other';
              if (!acc[groupName]) acc[groupName] = [];
              acc[groupName].push(opt);
              return acc;
          }, {})
        : null;

    const renderOptionButton = (opt: GlassSelectOption) => {
        const isSelected = opt.value === value;
        const badgeVariant = opt.badgeVariant || 'slate';

        return (
            <button
                key={opt.value}
                type="button"
                role="option"
                aria-selected={isSelected}
                onClick={() => handleSelect(opt.value)}
                className={`obs-touch-target-standard w-full text-left px-3.5 py-2.5 rounded-xl transition-all flex items-center justify-between gap-3 cursor-pointer border ${
                    isSelected
                        ? 'bg-indigo-500/15 border-indigo-500/35 text-slate-100 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.08)]'
                        : 'border-transparent text-slate-300 hover:bg-white/[0.06] hover:border-white/[0.08] hover:text-white'
                }`}
            >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                    {opt.dotColor ? (
                        <span className={`h-2 w-2 rounded-full shrink-0 ${opt.dotColor}`} />
                    ) : (
                        <span
                            className={`h-1.5 w-1.5 rounded-full shrink-0 transition-colors ${
                                isSelected
                                    ? 'bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.85)]'
                                    : 'bg-slate-600'
                            }`}
                        />
                    )}
                    <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-semibold leading-tight truncate">
                                {opt.label}
                            </span>
                            {opt.badge && (
                                <span
                                    className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${BADGE_STYLES[badgeVariant]}`}
                                >
                                    {opt.badge}
                                </span>
                            )}
                        </div>
                        {opt.description && (
                            <p className="text-xs text-slate-400 mt-0.5 leading-snug line-clamp-1">
                                {opt.description}
                            </p>
                        )}
                    </div>
                </div>

                <div className="flex items-center shrink-0">
                    {isSelected && <Check size={15} className="text-indigo-400" />}
                </div>
            </button>
        );
    };

    return (
        <div
            ref={containerRef}
            className={`relative w-full ${isOpen ? 'z-50' : 'z-20'} ${className}`}
        >
            <button
                type="button"
                aria-haspopup="listbox"
                aria-expanded={isOpen}
                aria-label={ariaLabel}
                onClick={() => setIsOpen((prev) => !prev)}
                className={`obs-touch-target-standard obs-gpu-120hz-interactive w-full bg-slate-900/90 hover:bg-slate-900 border rounded-xl px-4 py-3 text-left transition-all flex items-center justify-between gap-3 cursor-pointer ${
                    isOpen
                        ? 'border-indigo-500/50 ring-2 ring-indigo-500/20 shadow-[0_0_20px_rgba(99,102,241,0.18)]'
                        : 'border-white/10 hover:border-indigo-500/35'
                }`}
            >
                <div className="flex items-center gap-2.5 min-w-0 flex-1">
                    {selectedOption?.dotColor && (
                        <span className={`h-2 w-2 rounded-full shrink-0 ${selectedOption.dotColor}`} />
                    )}
                    <span className="text-sm font-medium text-slate-100 truncate">
                        {selectedOption?.label}
                    </span>
                    {selectedOption?.badge && (
                        <span
                            className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border shrink-0 ${
                                BADGE_STYLES[selectedOption.badgeVariant || 'slate']
                            }`}
                        >
                            {selectedOption.badge}
                        </span>
                    )}
                </div>
                <ChevronDown
                    size={16}
                    className={`shrink-0 transition-transform duration-200 ${
                        isOpen ? 'rotate-180 text-indigo-400' : 'text-slate-400'
                    }`}
                />
            </button>

            {isOpen && (
                <div
                    role="listbox"
                    aria-label={ariaLabel}
                    className="absolute left-0 right-0 top-full mt-2 z-50 bg-slate-950/95 backdrop-blur-2xl border border-white/15 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.85),0_0_25px_rgba(99,102,241,0.15)] p-1.5 max-h-72 overflow-y-auto obs-scroller space-y-1"
                >
                    {groupedOptions
                        ? Object.entries(groupedOptions).map(([groupName, groupOpts]) => (
                              <div key={groupName} className="space-y-1 pb-1 last:pb-0">
                                  <div className="px-3 pt-1.5 pb-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                                      {groupName}
                                  </div>
                                  {groupOpts.map(renderOptionButton)}
                              </div>
                          ))
                        : options.map(renderOptionButton)}
                </div>
            )}
        </div>
    );
}
