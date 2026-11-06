'use client';

import { useEffect, useRef, type ReactNode } from 'react';

export default function StreamingDialog({ name, onClose, children }: {
    name: string;
    onClose: () => void;
    children: ReactNode;
}) {
    const panelRef = useRef<HTMLDivElement>(null);
    const closeRef = useRef(onClose);
    useEffect(() => { closeRef.current = onClose; }, [onClose]);
    useEffect(() => {
        const panel = panelRef.current;
        if (!panel) return;
        const invoker = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        const focusable = () => Array.from(panel.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex="0"]'
        )).filter(element => !element.hidden && element.getAttribute('aria-hidden') !== 'true');
        (focusable()[0] || panel).focus();
        const onKey = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                closeRef.current();
            }
            if (event.key !== 'Tab') return;
            const elements = focusable();
            const first = elements[0] || panel;
            const last = elements[elements.length - 1] || panel;
            if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        };
        const containFocus = (event: FocusEvent) => {
            if (event.target instanceof Node && !panel.contains(event.target)) (focusable()[0] || panel).focus();
        };
        document.addEventListener('keydown', onKey);
        document.addEventListener('focusin', containFocus);
        return () => {
            document.removeEventListener('keydown', onKey);
            document.removeEventListener('focusin', containFocus);
            if (invoker?.isConnected) invoker.focus();
        };
    }, []);
    return <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4"
        onClick={event => { if (event.target === event.currentTarget) onClose(); }}>
        <div ref={panelRef} role="dialog" aria-modal="true" aria-label={name} tabIndex={-1}
            className="min-w-0 max-w-full max-h-[calc(100dvh-2rem)] overflow-y-auto">
            {children}
        </div>
    </div>;
}
