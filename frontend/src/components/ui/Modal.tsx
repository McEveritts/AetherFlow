'use client';

import { cn } from "@/lib/utils";
import React from "react";
import { X } from "lucide-react";

export interface ModalProps extends React.HTMLAttributes<HTMLDivElement> {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
}

export function Modal({ isOpen, onClose, title, children, className, ...props }: ModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Obsidian Backdrop */}
      <div 
        className="fixed inset-0 bg-black/80 backdrop-blur-md transition-opacity" 
        onClick={onClose}
      />
      
      {/* Obsidian V2 Modal Window */}
      <div
        className={cn(
          "relative w-full max-w-lg glass-panel rounded-2xl p-6 shadow-[0_24px_60px_rgba(0,0,0,0.9)] border border-indigo-500/30",
          "max-h-[calc(100dvh-2rem)] overflow-y-auto no-scrollbar",
          className
        )}
        {...props}
      >
        {/* Chromatic Top Edge Highlight */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-cyan-400/50 via-indigo-500/80 to-fuchsia-400/50 rounded-t-2xl pointer-events-none" />

        {title && (
          <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
            <h3 className="text-xl font-bold tracking-tight text-white">{title}</h3>
            <button 
              onClick={onClose}
              className="obs-touch-target-standard p-2 rounded-xl text-slate-400 hover:bg-white/10 hover:text-white transition-colors flex items-center justify-center"
              aria-label="Close Modal"
            >
              <X size={20} />
            </button>
          </div>
        )}
        <div className="text-slate-200 min-w-0 max-w-full">
          {children}
        </div>
      </div>
    </div>
  );
}
