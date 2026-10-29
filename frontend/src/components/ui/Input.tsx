import { cn } from "@/lib/utils";
import React from "react";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string | boolean;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, ...props }, ref) => {
    return (
      <div className="w-full space-y-1">
        <input
          type={type}
          className={cn(
            "flex min-h-[44px] h-10 w-full glass-input px-4 py-2 text-sm text-slate-200 placeholder:text-slate-500",
            "file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-not-allowed disabled:opacity-50",
            "obs-touch-target-standard transition-all duration-200",
            error && "border-red-500/80 focus:border-red-500 focus:ring-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.25)]",
            className
          )}
          ref={ref}
          {...props}
        />
        {typeof error === "string" && error && (
          <p className="text-xs text-red-400 font-medium px-1">{error}</p>
        )}
      </div>
    );
  }
);
Input.displayName = "Input";
