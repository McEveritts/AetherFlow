'use client';

import { cn } from "@/lib/utils";
import React, { useEffect, useId, useRef, type RefObject } from "react";
import { X } from "lucide-react";
import { createPortal } from "react-dom";

const modalStack: HTMLDivElement[] = [];
let originalBodyOverflow = '';

export interface ModalProps extends React.HTMLAttributes<HTMLDivElement> {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  initialFocusRef?: RefObject<HTMLElement | null>;
  returnFocusRef?: RefObject<HTMLElement | null>;
}

export function Modal({ isOpen, onClose, title, children, className, initialFocusRef, returnFocusRef, ...props }: ModalProps) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  useEffect(() => { closeRef.current = onClose; }, [onClose]);

  useEffect(() => {
    if (!isOpen) return;
    const panel = panelRef.current;
    if (!panel) return;
    const invoker = returnFocusRef?.current ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    if (modalStack.length === 0) {
      originalBodyOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    modalStack.push(panel);
    const isTopModal = () => modalStack[modalStack.length - 1] === panel;
    const getFocusable = () => Array.from(panel.querySelectorAll<HTMLElement>(
      'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex="0"]'
    )).filter(element => !element.hidden && element.getAttribute('aria-hidden') !== 'true');
    const preferredFocus = initialFocusRef?.current;
    (preferredFocus && panel.contains(preferredFocus) ? preferredFocus : getFocusable()[0] || panel).focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (!isTopModal()) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        closeRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = getFocusable();
      const first = focusable[0] || panel;
      const last = focusable[focusable.length - 1] || panel;
      if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    const containFocus = (event: FocusEvent) => {
      if (!isTopModal() || !(event.target instanceof Node) || panel.contains(event.target)) return;
      (getFocusable()[0] || panel).focus();
    };
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('focusin', containFocus);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('focusin', containFocus);
      const wasTopModal = isTopModal();
      const stackIndex = modalStack.lastIndexOf(panel);
      if (stackIndex >= 0) modalStack.splice(stackIndex, 1);
      if (modalStack.length === 0) document.body.style.overflow = originalBodyOverflow;
      const restoreTarget = invoker?.isConnected ? invoker : modalStack[modalStack.length - 1];
      if (wasTopModal) restoreTarget?.focus();
    };
  }, [isOpen, initialFocusRef, returnFocusRef]);

  if (!isOpen || typeof document === 'undefined') return null;

  return createPortal(
    <div className="fixed inset-0 z-[90] flex items-center justify-center p-4">
      {/* Obsidian Backdrop */}
      <div 
        className="fixed inset-0 bg-slate-950/60 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />
      
      {/* Obsidian V2 Modal Window */}
      <div
        {...props}
        ref={panelRef}
        className={cn(
          "relative w-full max-w-lg obs-telemetry-surface glass-panel rounded-2xl p-6 shadow-[0_24px_60px_rgba(0,0,0,0.6)] border border-indigo-500/30",
          "max-h-[calc(100dvh-2rem)] overflow-y-auto no-scrollbar",
          className
        )}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : props['aria-labelledby']}
        aria-label={title ? undefined : props['aria-label'] || 'Dialog'}
        tabIndex={-1}
      >
        {/* Chromatic Top Edge Highlight */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-cyan-400/50 via-indigo-500/80 to-fuchsia-400/50 rounded-t-2xl pointer-events-none" />

        {title && (
          <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
            <h3 id={titleId} className="text-xl font-bold tracking-tight text-white">{title}</h3>
            <button 
              type="button"
              onClick={onClose}
              className="obs-touch-target-standard p-2 rounded-xl text-slate-400 hover:bg-white/10 hover:text-white transition-colors flex items-center justify-center"
              aria-label={`Close ${title}`}
            >
              <X size={20} />
            </button>
          </div>
        )}
        <div className="text-slate-200 min-w-0 max-w-full">
          {children}
        </div>
      </div>
    </div>,
    document.body
  );
}
