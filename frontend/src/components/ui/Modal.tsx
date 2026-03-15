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
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity" 
        onClick={onClose}
      />
      
      {/* Modal Content */}
      <div
        className={cn(
          "relative w-full max-w-lg glass-card p-6 shadow-2xl animate-in fade-in zoom-in-95",
          className
        )}
        {...props}
      >
        {title && (
          <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
            <h3 className="text-xl font-bold tracking-tight text-white">{title}</h3>
            <button 
              onClick={onClose}
              className="p-1 rounded-full text-slate-400 hover:bg-white/10 hover:text-white transition-colors"
            >
              <X size={20} />
            </button>
          </div>
        )}
        <div className="text-slate-200">
          {children}
        </div>
      </div>
    </div>
  );
}
