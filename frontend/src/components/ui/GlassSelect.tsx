'use client';

import React, { useState, useRef, useEffect, useLayoutEffect, useCallback, useId } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, Check } from 'lucide-react';

export interface GlassSelectOption {
    value: string;
    label: string;
    description?: string;
    badge?: string;
    badgeVariant?: 'emerald' | 'amber' | 'indigo' | 'rose' | 'slate';
    dotColor?: string;
    group?: string;
    disabled?: boolean;
}

export interface GlassSelectProps {
    value: string;
    onChange: (value: string) => void;
    options: GlassSelectOption[];
    ariaLabel?: string;
    className?: string;
    disabled?: boolean;
}

const BADGE_STYLES: Record<NonNullable<GlassSelectOption['badgeVariant']>, string> = {
    emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    indigo: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
    rose: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
    slate: 'bg-slate-800/90 text-slate-300 border-white/10',
};

export default function GlassSelect({
    value,
    onChange,
    options,
    ariaLabel,
    className = '',
    disabled = false,
}: GlassSelectProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [portalHost, setPortalHost] = useState<Element | null>(null);
    const listboxId = useId();
    const [bounds, setBounds] = useState({
        opensUp: false,
        maxHeight: 0,
        top: 0,
        left: 0,
        width: 0,
    });
    const containerRef = useRef<HTMLDivElement>(null);
    const triggerRef = useRef<HTMLButtonElement>(null);
    const listboxRef = useRef<HTMLDivElement>(null);

    const selectedOption = options.find((candidateOption) => candidateOption.value === value) || options[0];

    const updateBounds = useCallback(() => {
        const containerElement = containerRef.current;
        if (!containerElement) return;

        setPortalHost(containerElement.closest('[data-overlay-boundary]') ?? containerElement.ownerDocument.body);
        const anchorRect = containerElement.getBoundingClientRect();
        const currentWindow = typeof window !== 'undefined' ? window : null;
        if (!currentWindow) return;

        const currentViewport = currentWindow.visualViewport;
        const viewportTop = currentViewport ? currentViewport.offsetTop : 0;
        const viewportHeight = currentViewport ? currentViewport.height : currentWindow.innerHeight;
        const viewportBottom = viewportTop + viewportHeight;

        const currentDocument = typeof document !== 'undefined' ? document : null;
        const headerElement = currentDocument?.querySelector('header');
        const headerRect = headerElement ? headerElement.getBoundingClientRect() : null;
        const headerBottom = headerRect && headerRect.height > 0 ? headerRect.bottom : viewportTop;
        const upperBound = Math.max(viewportTop, headerBottom);

        const dockElement = currentDocument?.querySelector('nav[aria-label="Mobile Bottom Navigation"]');
        const dockRect = dockElement ? dockElement.getBoundingClientRect() : null;
        const dockTop = dockRect && dockRect.height > 0 && dockRect.top < viewportBottom ? dockRect.top : viewportBottom;
        const lowerBound = Math.min(viewportBottom, dockTop);

        if (anchorRect.bottom < upperBound || anchorRect.top > lowerBound) {
            setIsOpen(false);
            return;
        }

        const marginSpacing = 8;
        const triggerSpacing = 8;
        const spaceBelow = Math.max(0, lowerBound - marginSpacing - anchorRect.bottom - triggerSpacing);
        const spaceAbove = Math.max(0, anchorRect.top - triggerSpacing - upperBound - marginSpacing);

        const listboxElement = listboxRef.current;
        const measuredHeight = Math.min(listboxElement && listboxElement.scrollHeight > 0 ? listboxElement.scrollHeight + 2 : 288, 288);
        const shouldOpenUp = measuredHeight > spaceBelow && spaceAbove > spaceBelow;
        const maxHeight = Math.min(288, shouldOpenUp ? spaceAbove : spaceBelow);
        const viewportLeft = currentViewport?.offsetLeft ?? 0;
        const viewportWidth = currentViewport?.width ?? (currentDocument?.documentElement.clientWidth || currentWindow.innerWidth);
        const width = Math.max(0, Math.min(Math.max(anchorRect.width, 280), viewportWidth - marginSpacing * 2));
        const left = Math.max(viewportLeft + marginSpacing, Math.min(anchorRect.left, viewportLeft + viewportWidth - marginSpacing - width));
        const top = shouldOpenUp
            ? anchorRect.top - triggerSpacing - Math.min(measuredHeight, maxHeight)
            : anchorRect.bottom + triggerSpacing;

        setBounds((previousBounds) => {
            if (previousBounds.opensUp === shouldOpenUp && previousBounds.maxHeight === maxHeight && previousBounds.top === top && previousBounds.left === left && previousBounds.width === width) {
                return previousBounds;
            }
            return { opensUp: shouldOpenUp, maxHeight, top, left, width };
        });
    }, []);

    useLayoutEffect(() => {
        if (!isOpen) return;

        updateBounds();

        const handleWindowResize = () => updateBounds();
        const handleWindowScroll = () => updateBounds();
        const currentViewport = typeof window !== 'undefined' ? window.visualViewport : null;

        window.addEventListener('resize', handleWindowResize);
        window.addEventListener('scroll', handleWindowScroll, true);
        currentViewport?.addEventListener('resize', handleWindowResize);
        currentViewport?.addEventListener('scroll', handleWindowScroll);

        let resizeObserverInstance: ResizeObserver | null = null;
        if (typeof ResizeObserver !== 'undefined') {
            resizeObserverInstance = new ResizeObserver(() => {
                updateBounds();
            });
            if (triggerRef.current) {
                resizeObserverInstance.observe(triggerRef.current);
            }
            const containingMain = containerRef.current?.closest('main') || containerRef.current?.closest('[data-scroller="main"]') || containerRef.current?.ownerDocument?.querySelector('main');
            if (containingMain) {
                resizeObserverInstance.observe(containingMain);
            }
        }

        return () => {
            window.removeEventListener('resize', handleWindowResize);
            window.removeEventListener('scroll', handleWindowScroll, true);
            currentViewport?.removeEventListener('resize', handleWindowResize);
            currentViewport?.removeEventListener('scroll', handleWindowScroll);
            if (resizeObserverInstance) {
                resizeObserverInstance.disconnect();
            }
        };
    }, [isOpen, options, updateBounds]);

    useLayoutEffect(() => {
        if (!isOpen) return;
        updateBounds();
    }, [isOpen, bounds.width, updateBounds]);

    useEffect(() => {
        if (!isOpen) return;

        const handleClickOutside = (event: PointerEvent | MouseEvent) => {
            const containerElement = containerRef.current;
            if (containerElement && !containerElement.contains(event.target as Node) && !listboxRef.current?.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };

        const handleDocumentKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                setIsOpen(false);
                triggerRef.current?.focus();
            }
        };

        document.addEventListener('pointerdown', handleClickOutside);
        document.addEventListener('keydown', handleDocumentKeyDown);

        return () => {
            document.removeEventListener('pointerdown', handleClickOutside);
            document.removeEventListener('keydown', handleDocumentKeyDown);
        };
    }, [isOpen]);

    useEffect(() => {
        if (!isOpen) return;

        const listboxElement = listboxRef.current;
        if (!listboxElement) return;

        const currentOption = listboxElement.querySelector<HTMLButtonElement>('[role="option"]:focus:not(:disabled)');
        if (currentOption) return;
        const selectedOptionElement = listboxElement.querySelector<HTMLButtonElement>(
            '[role="option"][aria-selected="true"]:not(:disabled)'
        );
        const firstOptionElement = listboxElement.querySelector<HTMLButtonElement>(
            '[role="option"]:not(:disabled)'
        );
        const targetOption = selectedOptionElement || firstOptionElement;
        (targetOption || listboxElement).focus();
        targetOption?.scrollIntoView?.({ block: 'nearest' });
    }, [isOpen, options, value]);

    const handleSelect = (optionValue: string) => {
        onChange(optionValue);
        setIsOpen(false);
        triggerRef.current?.focus();
    };

    const handleTriggerClick = () => {
        if (disabled) return;
        if (!isOpen) {
            updateBounds();
        }
        setIsOpen((previousState) => !previousState);
    };

    const handleTriggerKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
        if (disabled) return;

        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (!isOpen) {
                updateBounds();
                setIsOpen(true);
            } else {
                const listboxElement = listboxRef.current;
                if (!listboxElement) return;
                const availableOptions = Array.from(
                    listboxElement.querySelectorAll<HTMLButtonElement>('[role="option"]:not(:disabled)')
                );
                if (availableOptions.length === 0) return;
                const selectedOptionElement = listboxElement.querySelector<HTMLButtonElement>(
                    '[role="option"][aria-selected="true"]:not(:disabled)'
                );
                const targetOption = selectedOptionElement || availableOptions[0];
                targetOption?.focus();
                targetOption?.scrollIntoView?.({ block: 'nearest' });
            }
        } else if (event.key === 'Enter' || event.key === ' ') {
            if (!isOpen) {
                event.preventDefault();
                updateBounds();
                setIsOpen(true);
            }
        } else if (event.key === 'Escape' && isOpen) {
            event.preventDefault();
            event.stopPropagation();
            setIsOpen(false);
            triggerRef.current?.focus();
        }
    };

    const handleListboxKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
        const listboxElement = listboxRef.current;
        if (!listboxElement) return;

        if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            setIsOpen(false);
            triggerRef.current?.focus();
            return;
        }

        if (event.key === 'Tab') {
            triggerRef.current?.focus();
            setIsOpen(false);
            return;
        }

        const availableOptions = Array.from(
            listboxElement.querySelectorAll<HTMLButtonElement>('[role="option"]:not(:disabled)')
        );
        if (availableOptions.length === 0) return;

        const currentActiveElement = document.activeElement as HTMLButtonElement | null;
        const currentIndex = currentActiveElement ? availableOptions.indexOf(currentActiveElement) : -1;

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            const nextIndex = currentIndex === -1 ? 0 : (currentIndex + 1) % availableOptions.length;
            const nextOption = availableOptions[nextIndex];
            nextOption?.focus();
            nextOption?.scrollIntoView?.({ block: 'nearest' });
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            const nextIndex = currentIndex === -1 ? availableOptions.length - 1 : (currentIndex - 1 + availableOptions.length) % availableOptions.length;
            const nextOption = availableOptions[nextIndex];
            nextOption?.focus();
            nextOption?.scrollIntoView?.({ block: 'nearest' });
        } else if (event.key === 'Home') {
            event.preventDefault();
            const firstOption = availableOptions[0];
            firstOption?.focus();
            firstOption?.scrollIntoView?.({ block: 'nearest' });
        } else if (event.key === 'End') {
            event.preventDefault();
            const lastOption = availableOptions[availableOptions.length - 1];
            lastOption?.focus();
            lastOption?.scrollIntoView?.({ block: 'nearest' });
        } else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            if (currentActiveElement && currentActiveElement.getAttribute('role') === 'option') {
                currentActiveElement.click();
            }
        }
    };

    const hasGroups = options.some((optionItem) => Boolean(optionItem.group));
    const groupedOptions = hasGroups
        ? options.reduce<Record<string, GlassSelectOption[]>>((accumulator, optionItem) => {
              const groupName = optionItem.group || 'Other';
              if (!accumulator[groupName]) accumulator[groupName] = [];
              accumulator[groupName].push(optionItem);
              return accumulator;
          }, {})
        : null;

    const renderOptionButton = (optionItem: GlassSelectOption) => {
        const isSelected = optionItem.value === value;
        const badgeVariant = optionItem.badgeVariant || 'slate';

        return (
            <button
                key={optionItem.value}
                type="button"
                role="option"
                aria-selected={isSelected}
                disabled={optionItem.disabled}
                aria-disabled={optionItem.disabled}
                tabIndex={-1}
                onClick={() => {
                    if (!optionItem.disabled) {
                        handleSelect(optionItem.value);
                    }
                }}
                className={`obs-touch-target-standard w-full text-left px-3.5 py-2.5 rounded-xl transition-all flex items-center justify-between gap-3 border ${
                    optionItem.disabled
                        ? 'opacity-40 cursor-not-allowed pointer-events-none border-transparent text-slate-400'
                        : isSelected
                            ? 'bg-indigo-500/15 border-indigo-500/35 text-slate-100 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.08)] cursor-pointer'
                            : 'border-transparent text-slate-300 hover:bg-white/[0.06] hover:border-white/[0.08] hover:text-white cursor-pointer'
                }`}
            >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                    {optionItem.dotColor ? (
                        <span className={`h-2 w-2 rounded-full shrink-0 ${optionItem.dotColor}`} />
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
                            <span className="text-sm font-semibold leading-tight break-words [overflow-wrap:anywhere]">
                                {optionItem.label}
                            </span>
                            {optionItem.badge && (
                                <span
                                    className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${BADGE_STYLES[badgeVariant]}`}
                                >
                                    {optionItem.badge}
                                </span>
                            )}
                        </div>
                        {optionItem.description && (
                            <p className="text-xs text-slate-400 mt-0.5 leading-snug break-words">
                                {optionItem.description}
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
                ref={triggerRef}
                type="button"
                aria-haspopup="listbox"
                aria-controls={isOpen ? listboxId : undefined}
                aria-owns={isOpen ? listboxId : undefined}
                aria-expanded={isOpen}
                aria-label={ariaLabel}
                disabled={disabled}
                aria-disabled={disabled}
                onClick={handleTriggerClick}
                onKeyDown={handleTriggerKeyDown}
                className={`obs-touch-target-standard obs-gpu-120hz-interactive w-full bg-slate-900/90 hover:bg-slate-900 border rounded-xl px-4 py-3 text-left transition-all flex items-center justify-between gap-3 ${
                    disabled
                        ? 'opacity-50 cursor-not-allowed pointer-events-none border-white/5'
                        : 'cursor-pointer ' + (isOpen
                            ? 'border-indigo-500/50 ring-2 ring-indigo-500/20 shadow-[0_0_20px_rgba(99,102,241,0.18)]'
                            : 'border-white/10 hover:border-indigo-500/35')
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
                            className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border shrink-0 ${
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

            {isOpen && portalHost && createPortal(
                <div
                    id={listboxId}
                    ref={listboxRef}
                    role="listbox"
                    aria-label={ariaLabel}
                    tabIndex={-1}
                    onKeyDown={handleListboxKeyDown}
                    data-placement={bounds.opensUp ? 'top' : 'bottom'}
                    style={{ maxHeight: bounds.maxHeight, top: bounds.top, left: bounds.left, width: bounds.width }}
                    className="obs-select-listbox fixed z-[80] bg-slate-950 backdrop-blur-2xl border border-white/15 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.85),0_0_25px_rgba(99,102,241,0.15)] p-1.5 overflow-y-auto obs-scroller space-y-1"
                >
                    <div aria-hidden="true" className="sticky -top-1.5 -mx-1.5 -mt-1.5 z-10 flex items-center justify-between gap-2 border-b border-white/10 bg-slate-950 px-[18px] py-2.5 text-xs text-slate-400">
                        <span className="min-w-0 break-words">{ariaLabel || 'Choose an option'}</span>
                        <span className="shrink-0">{options.length} options · ↕</span>
                    </div>
                    {groupedOptions
                        ? Object.entries(groupedOptions).map(([groupName, groupOpts]) => (
                              <div key={groupName} className="space-y-1 pb-1 last:pb-0">
                                  <div className="px-3 pt-1.5 pb-0.5 text-xs font-bold uppercase tracking-wider text-slate-400">
                                      {groupName}
                                  </div>
                                  {groupOpts.map(renderOptionButton)}
                              </div>
                          ))
                        : options.map(renderOptionButton)}
                </div>,
                portalHost
            )}
        </div>
    );
}
