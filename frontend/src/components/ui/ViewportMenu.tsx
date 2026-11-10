'use client';

import { useLayoutEffect, useRef, useState, type HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

interface ViewportMenuProps extends HTMLAttributes<HTMLDivElement> {
    onDismiss: () => void;
    align?: 'left' | 'right';
    initialFocus?: 'menu' | 'firstItem';
}

export function ViewportMenu({
    children,
    className,
    onDismiss,
    style,
    align = 'right',
    initialFocus = 'menu',
    ...props
}: ViewportMenuProps) {
    const menuRef = useRef<HTMLDivElement>(null);
    const dismissRef = useRef(onDismiss);
    const [bounds, setBounds] = useState({ opensUp: false, maxHeight: 0 });

    useLayoutEffect(() => {
        dismissRef.current = onDismiss;
    }, [onDismiss]);

    useLayoutEffect(() => {
        const menu = menuRef.current;
        const anchor = menu?.parentElement;
        if (!menu || !anchor) return;
        const updateBounds = () => {
            const anchorRect = anchor.getBoundingClientRect();
            const viewport = window.visualViewport;
            const viewportTop = viewport?.offsetTop ?? 0;
            const viewportBottom = viewportTop + (viewport?.height ?? window.innerHeight);
            const headerRect = document.querySelector('header')?.getBoundingClientRect();
            const dockRect = document.querySelector('nav[aria-label="Mobile Bottom Navigation"]')?.getBoundingClientRect();
            const upperBound = Math.max(viewportTop, headerRect?.bottom ?? viewportTop);
            const lowerBound = Math.min(viewportBottom, dockRect?.height ? dockRect.top : viewportBottom);
            const spaceBelow = Math.max(0, lowerBound - anchorRect.bottom - 8);
            const spaceAbove = Math.max(0, anchorRect.top - upperBound - 8);
            if (anchorRect.bottom < upperBound || anchorRect.top > lowerBound) {
                dismissRef.current();
                return;
            }
            const opensUp = menu.scrollHeight > spaceBelow && spaceAbove > spaceBelow;
            const maxHeight = opensUp ? spaceAbove : spaceBelow;
            setBounds(previous => previous.opensUp === opensUp && previous.maxHeight === maxHeight
                ? previous : { opensUp, maxHeight });
        };
        updateBounds();
        if (initialFocus === 'firstItem') {
            menu.querySelector<HTMLElement>('[role="menuitem"]:not(:disabled)')?.focus();
        } else {
            menu.focus();
        }
        window.addEventListener('resize', updateBounds);
        window.addEventListener('scroll', updateBounds, true);
        window.visualViewport?.addEventListener('resize', updateBounds);
        return () => {
            window.removeEventListener('resize', updateBounds);
            window.removeEventListener('scroll', updateBounds, true);
            window.visualViewport?.removeEventListener('resize', updateBounds);
        };
    }, [initialFocus]);

    return (
        <div
            tabIndex={props.tabIndex ?? -1}
            {...props}
            ref={menuRef}
            className={cn(
                'absolute z-30 overflow-y-auto custom-scrollbar focus:outline-none',
                align === 'left' ? 'left-0' : 'right-0',
                bounds.opensUp ? 'bottom-full mb-1.5' : 'top-full mt-1.5',
                className
            )}
            style={{ ...style, maxHeight: bounds.maxHeight || undefined }}
            onKeyDown={(event) => {
                const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled)'));
                if (event.key === 'Escape' || event.key === 'Tab') {
                    if (event.key === 'Escape') {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    const trigger = (event.currentTarget.id
                        ? document.querySelector<HTMLElement>(`[aria-controls="${event.currentTarget.id}"]`)
                        : null) ?? event.currentTarget.parentElement?.querySelector<HTMLElement>('[aria-haspopup="menu"]');
                    trigger?.focus();
                    dismissRef.current();
                } else if (items.length && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
                    event.preventDefault();
                    const currentIndex = items.indexOf(document.activeElement as HTMLElement);
                    let nextIndex = 0;
                    if (event.key === 'Home') {
                        nextIndex = 0;
                    } else if (event.key === 'End') {
                        nextIndex = items.length - 1;
                    } else if (currentIndex === -1) {
                        nextIndex = event.key === 'ArrowUp' ? items.length - 1 : 0;
                    } else {
                        nextIndex = (currentIndex + (event.key === 'ArrowUp' ? -1 : 1) + items.length) % items.length;
                    }
                    items[nextIndex]?.focus();
                }
                props.onKeyDown?.(event);
            }}
        >
            {children}
        </div>
    );
}
